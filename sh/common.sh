#!/system/bin/sh
# shellcheck shell=sh disable=SC2034
#
# sh/common.sh - shared by post-fs-data.sh, service.sh, ctl.sh, uninstall.sh
#
# Only defines variables and functions; sourcing it does nothing else.
# POSIX sh: runs under mksh + toybox (ksu.exec, WebUI) and busybox ash in
# standalone mode (the root manager's scripts / installer). No bashisms.

MODULE_ID="lan-cloak"
ADB="${LANC_ADB:-/data/adb}"   # root of the root manager's files (sibling modules)
MODDIR="${MODDIR:-/data/adb/modules/$MODULE_ID}"

# ── Paths ────────────────────────────────────────────────────────────────────
#   /data/adb/lan-cloak/
#     settings.conf   settings
#     logs/           lan-cloak.log (module), dhcp-guard.log (DHCP guard daemon)
#     state/          runtime files, cleared at boot (status: read by siblings)
#     backup/         original values the module changed (device name, MAC)
DATA_DIR="${LANC_DATA:-/data/adb/lan-cloak}"
CONF="$DATA_DIR/settings.conf"
STATE_DIR="$DATA_DIR/state"
LOGS_DIR="$DATA_DIR/logs"
BACKUP_DIR="$DATA_DIR/backup"
LOG="$LOGS_DIR/lan-cloak.log"
GUARD_LOG="$LOGS_DIR/dhcp-guard.log"
MODPROP="$MODDIR/module.prop"

STATUS_FILE="$STATE_DIR/status"      # contract (key=value, keys stay stable)
WD_PIDFILE="$STATE_DIR/watchdog.pid"
TICK_FILE="$STATE_DIR/tick"
LOCK_DIR="$STATE_DIR/lock"
TZ_FILE="$STATE_DIR/tz"              # date +%z for the daemon's log times
GUARD_PIDFILE="$STATE_DIR/dhcp-guard.pid"
GUARD_FAIL="$STATE_DIR/dhcp-guard.fail"   # <epoch> <error> of the last failed start
SINCE_FILE="$STATE_DIR/since"

# The eBPF helper (loader + DHCP guard daemon), see src/lanc-bpf.c
BPF="${LANC_BPF:-$MODDIR/bin/lanc-bpf}"

# Watchdog period. The DHCP guard reacts to Wi-Fi events by itself (netlink),
# the watchdog only checks that it runs and that the firewall rules are there.
# Faster right after boot, while netd sets up its own chains.
TICK=${LANC_TICK:-10}
TICK_BOOT=${LANC_TICK_BOOT:-2}
BOOT_FAST=${LANC_BOOT_FAST:-120}   # seconds of TICK_BOOT after the watchdog starts
# A guard that failed to start (kernel refused the program) is retried this
# often, not on every tick.
GUARD_RETRY=300

# iptables chains (filter OUTPUT, jump only for the Wi-Fi interface)
C_OUT="LANC_OUT"
C_OUT6="LANC_OUT6"

# ── Settings ─────────────────────────────────────────────────────────────────
# KEY=value, read FRESH from the file on every call: the long-lived watchdog
# must never undo a change made a moment ago from ctl.sh / the WebUI.
SETTINGS_KEYS="ENABLED DHCP_HOSTNAME DHCP_VENDOR DHCP_PRL BLOCK_MDNS BLOCK_SSDP BLOCK_LLMNR WIFI_IFACE"

conf_default() {
  case "$1" in
    ENABLED | DHCP_HOSTNAME | DHCP_VENDOR | DHCP_PRL) echo 1 ;;
    BLOCK_MDNS | BLOCK_SSDP | BLOCK_LLMNR) echo 1 ;;
    WIFI_IFACE) echo auto ;;
  esac
}

conf_valid() { # <KEY> <value>
  case "$1" in
    ENABLED | DHCP_HOSTNAME | DHCP_VENDOR | DHCP_PRL | BLOCK_MDNS | BLOCK_SSDP | BLOCK_LLMNR)
      case "$2" in 0 | 1) return 0 ;; esac ;;
    WIFI_IFACE)
      [ "$2" = auto ] && return 0
      _iface_name_ok "$2" && return 0 ;;
  esac
  return 1
}

_iface_name_ok() {
  case "$1" in "" | *[!A-Za-z0-9_.-]* | .* ) return 1 ;; esac
  [ "${#1}" -le 15 ]
}

# All settings in one read: sets S_<KEY> for every key (default when the
# line is missing or invalid). One file read instead of one per key.
conf_load() {
  for _k in $SETTINGS_KEYS; do eval "S_$_k=\$(conf_default $_k)"; done
  if [ -f "$CONF" ]; then
    while IFS='=' read -r _k _v; do
      case " $SETTINGS_KEYS " in *" $_k "*) ;; *) continue ;; esac
      conf_valid "$_k" "$_v" && eval "S_$_k=\$_v"
    done < "$CONF"
  fi
  unset _k _v
}

conf_get() { # <KEY> -> value (default when missing or invalid)
  _cv=$(sed -n "s/^$1=//p" "$CONF" 2>/dev/null | tail -n 1)
  conf_valid "$1" "$_cv" || _cv=$(conf_default "$1")
  echo "$_cv"
  unset _cv
}

conf_set() { # <KEY> <value>
  conf_valid "$1" "$2" || return 1
  mkdir -p "${CONF%/*}" 2>/dev/null
  { grep -v "^$1=" "$CONF" 2>/dev/null; echo "$1=$2"; } > "$CONF.tmp" &&
    mv -f "$CONF.tmp" "$CONF"
}

# Missing keys are added with their default; existing values are kept.
conf_init() {
  mkdir -p "${CONF%/*}" 2>/dev/null
  [ -f "$CONF" ] || : > "$CONF"
  for _k in $SETTINGS_KEYS; do
    grep -q "^$_k=" "$CONF" 2>/dev/null || echo "$_k=$(conf_default "$_k")" >> "$CONF"
  done
  unset _k
}

# ── Logging ──────────────────────────────────────────────────────────────────
# Before Android has set the clock (post-fs-data) the date is 1970: the
# time since boot is written instead, "boot+12.34s".
_ts() {
  _tsd=$(date '+%Y-%m-%d %H:%M:%S')
  case "$_tsd" in
    19[0-9][0-9]-* | 200[0-9]-* | 201[0-9]-*) _tsu=""; read -r _tsu _tsx < /proc/uptime 2>/dev/null; echo "boot+${_tsu:-?}s" ;;
    *) echo "$_tsd" ;;
  esac
  unset _tsd _tsu _tsx
}
# The clock is set (not 1970 any more)
clock_ok() { [ "$(date +%s)" -ge 1577836800 ] 2>/dev/null; }
# The phone is shutting down / rebooting (netd and iptables go away)
shutting_down() { [ -n "$(getprop sys.powerctl 2>/dev/null)" ]; }
log_info()  { echo "$(_ts) [INFO] $*"  >> "$LOG"; }
log_warn()  { echo "$(_ts) [WARN] $*"  >> "$LOG"; }
log_error() { echo "$(_ts) [ERROR] $*" >> "$LOG"; }

# Keep the last 1000 lines. Trimmed IN PLACE (same file): the DHCP guard
# keeps its log open in append mode, a new file would never see its lines.
log_trim() { # [file]
  _lf=${1:-$LOG}
  [ -f "$_lf" ] || { unset _lf; return 0; }
  _lc=$(wc -l < "$_lf" 2>/dev/null)
  if [ "${_lc:-0}" -gt 1200 ] 2>/dev/null; then
    tail -n 1000 "$_lf" > "$_lf.tmp" 2>/dev/null && cat "$_lf.tmp" > "$_lf" 2>/dev/null
    rm -f "$_lf.tmp"
  fi
  unset _lf _lc
}

log_clear() { # [file]   empty in place (same file, same owner/mode)
  rm -f "${1:-$LOG}.tmp"
  : > "${1:-$LOG}"
}

# Local time offset for the daemon (it cannot read Android's time zone
# data). Written when it changed; the daemon reads it every minute.
tz_update() {
  _tz=$(date +%z 2>/dev/null)
  case "$_tz" in [+-][0-9][0-9][0-9][0-9]) ;; *) unset _tz; return 0 ;; esac
  _old=""; read -r _old 2>/dev/null < "$TZ_FILE"
  [ "$_old" = "$_tz" ] || echo "$_tz" > "$TZ_FILE" 2>/dev/null
  unset _tz _old
}

# ── Tools ────────────────────────────────────────────────────────────────────
# iptables / ip6tables always wait for the xtables lock (-w). Without it a
# command fails at once while netd or another module holds the lock, and a
# failed check reads as "rule missing". The working -w form is probed once
# per boot.
IPT_WAIT_FILE="$STATE_DIR/ipt_wait"
if [ -z "$IPT4_BIN" ]; then
  IPT4_BIN=$(command -v iptables 2>/dev/null)
  case "$IPT4_BIN" in /*) ;; *) IPT4_BIN="" ;; esac
fi
if [ -z "$IPT6_BIN" ]; then
  IPT6_BIN=$(command -v ip6tables 2>/dev/null)
  case "$IPT6_BIN" in /*) ;; *) IPT6_BIN="" ;; esac
fi
IPT_W="-"

_ipt_wait_init() {
  [ "$IPT_W" != "-" ] && return 0
  if [ -f "$IPT_WAIT_FILE" ]; then
    IPT_W=""
    read -r IPT_W 2>/dev/null < "$IPT_WAIT_FILE"
    return 0
  fi
  [ -n "$IPT4_BIN" ] || { IPT_W=""; return 0; }
  for _iw in "-w 5" "-w"; do
    # shellcheck disable=SC2086
    if "$IPT4_BIN" $_iw -S OUTPUT >/dev/null 2>&1; then
      IPT_W=$_iw
      mkdir -p "$STATE_DIR" 2>/dev/null
      echo "$IPT_W" > "$IPT_WAIT_FILE" 2>/dev/null
      unset _iw
      return 0
    fi
  done
  IPT_W=""; unset _iw
  _ipt_w_retry=1
}

iptables() {
  _ipt_wait_init
  [ -n "$IPT4_BIN" ] || return 127
  # shellcheck disable=SC2086
  "$IPT4_BIN" $IPT_W "$@"
  _ipt_rc=$?
  [ -n "$_ipt_w_retry" ] && { IPT_W="-"; unset _ipt_w_retry; }
  return $_ipt_rc
}

ip6tables() {
  _ipt_wait_init
  [ -n "$IPT6_BIN" ] || return 127
  # shellcheck disable=SC2086
  "$IPT6_BIN" $IPT_W "$@"
  _ipt_rc=$?
  [ -n "$_ipt_w_retry" ] && { IPT_W="-"; unset _ipt_w_retry; }
  return $_ipt_rc
}

# iptables-restore: all changes of a family in ONE call (the xtables lock is
# taken once - netd must never wait for us).
if [ -z "$IPTR4_BIN" ]; then
  IPTR4_BIN=$(command -v iptables-restore 2>/dev/null)
  case "$IPTR4_BIN" in /*) ;; *) IPTR4_BIN="" ;; esac
fi
if [ -z "$IPTR6_BIN" ]; then
  IPTR6_BIN=$(command -v ip6tables-restore 2>/dev/null)
  case "$IPTR6_BIN" in /*) ;; *) IPTR6_BIN="" ;; esac
fi
IPTR_W="-"
IPTR_WAIT_FILE="$STATE_DIR/iptr_wait"

# Reading the tables WITHOUT the xtables lock: iptables-save never takes it.
# The watchdog's checks run every few seconds and must not compete with netd
# (or wg-quick, which fails outright when the lock is held).
if [ -z "$IPTS4_BIN" ]; then
  IPTS4_BIN=$(command -v iptables-save 2>/dev/null)
  case "$IPTS4_BIN" in /*) ;; *) IPTS4_BIN="" ;; esac
fi
if [ -z "$IPTS6_BIN" ]; then
  IPTS6_BIN=$(command -v ip6tables-save 2>/dev/null)
  case "$IPTS6_BIN" in /*) ;; *) IPTS6_BIN="" ;; esac
fi

# ipt_dump <4|6> <table>: the table in "iptables -S" form (-P / -N / -A
# lines), from iptables-save when available. Fails if the table cannot be
# read (e.g. no IPv6). Read with counters (-c): for the module's own rules
# an extra "#C <packets> <port>" line comes first (the blocked-packet
# counts in the status); every other reader skips "#" lines.
ipt_dump() {
  if [ "$1" = 6 ]; then _db=$IPTS6_BIN; _dc=ip6tables; else _db=$IPTS4_BIN; _dc=iptables; fi
  if [ -n "$_db" ]; then
    _dt=$("$_db" -c -t "$2" 2>/dev/null) || _dt=$("$_db" -t "$2" 2>/dev/null) || { unset _db _dc _dt; return 1; }
    case "$_dt" in *"*$2"*) ;; *) unset _db _dc _dt; return 1 ;; esac
    printf '%s\n' "$_dt" | sed -n -e 's/^:\([^ ]*\) - .*/-N \1/p' -e 's/^:\([^ ]*\) \([A-Z][A-Z]*\) .*/-P \1 \2/p' \
      -e '/^\[[0-9]*:[0-9]*\] -A LANC_OUT/{h;s/^\[\([0-9]*\):.*-[ds]port \([0-9]*\) .*/#C \1 \2/p;g;}' \
      -e 's/^\[[0-9]*:[0-9]*\] //' -e '/^-A /p'
    unset _db _dc _dt
    return 0
  fi
  "$_dc" -t "$2" -S 2>/dev/null; _dr=$?
  unset _db _dc
  return $_dr
}

# ip6tables usable at all (always on Android; not in every test sandbox)
has_ip6t() { [ -n "$IPT6_BIN" ] && ipt_dump 6 filter >/dev/null 2>&1; }

_iptr_wait_init() {
  [ "$IPTR_W" != "-" ] && return 0
  if [ -f "$IPTR_WAIT_FILE" ]; then
    IPTR_W=""; read -r IPTR_W 2>/dev/null < "$IPTR_WAIT_FILE"; return 0
  fi
  IPTR_W=""
  [ -n "$IPTR4_BIN" ] || return 0
  for _iw in "-w 5" "-w" ""; do
    # shellcheck disable=SC2086
    if printf '*filter\nCOMMIT\n' | "$IPTR4_BIN" $_iw --noflush >/dev/null 2>&1; then
      IPTR_W=$_iw
      mkdir -p "$STATE_DIR" 2>/dev/null
      echo "$IPTR_W" > "$IPTR_WAIT_FILE" 2>/dev/null
      break
    fi
  done
  unset _iw
}

_ipt_line() { # <cmd> <table> <rule line>
  # shellcheck disable=SC2086
  "$1" -t "$2" $3 2>/dev/null
}

# ipt_restore <4|6>  - reads iptables-restore input (applied with
# --noflush) on stdin. Without the restore tool: one command per line.
ipt_restore() {
  if [ "$1" = 6 ]; then _rb=$IPTR6_BIN; _rt=ip6tables; else _rb=$IPTR4_BIN; _rt=iptables; fi
  if [ -n "$_rb" ]; then
    _iptr_wait_init
    # shellcheck disable=SC2086
    "$_rb" $IPTR_W --noflush
    _rr=$?
    unset _rb _rt
    return $_rr
  fi
  _rtab=filter; _rr=0
  while read -r _rl; do
    case "$_rl" in
      '' | '#'*) ;;
      '*'*) _rtab=${_rl#\*} ;;
      COMMIT) ;;
      :*) _rn=${_rl#:}; _rn=${_rn%% *}
          "$_rt" -t "$_rtab" -N "$_rn" 2>/dev/null || "$_rt" -t "$_rtab" -F "$_rn" 2>/dev/null || _rr=1 ;;
      *) _ipt_line "$_rt" "$_rtab" "$_rl" || _rr=1 ;;
    esac
  done
  unset _rb _rt _rtab _rl _rn
  return $_rr
}

# ── Lock ─────────────────────────────────────────────────────────────────────
# The watchdog and a ctl.sh command can apply at the same moment. The lock
# holds the owner's pid; a lock whose owner is gone is taken over.
lanc_lock() {
  mkdir -p "$STATE_DIR" 2>/dev/null
  _lw=0
  while ! mkdir "$LOCK_DIR" 2>/dev/null; do
    _lp=""
    read -r _lp 2>/dev/null < "$LOCK_DIR/pid"
    if [ -n "$_lp" ] && ! kill -0 "$_lp" 2>/dev/null; then
      rm -rf "$LOCK_DIR"; continue
    fi
    _lw=$((_lw + 1))
    if [ "$_lw" -ge 100 ]; then   # ~10 s: owner hung
      rm -rf "$LOCK_DIR"; continue
    fi
    sleep 0.1 2>/dev/null || sleep 1
  done
  echo "$$" > "$LOCK_DIR/pid"
  unset _lw _lp
}
lanc_unlock() { rm -rf "$LOCK_DIR" 2>/dev/null; }

# ── Wi-Fi interface ──────────────────────────────────────────────────────────
# Android's Wi-Fi client interface (normally wlan0). Hotspot interfaces and
# mobile data are never touched.
wifi_iface() {
  _wi=$(conf_get WIFI_IFACE)
  if [ "$_wi" = auto ]; then
    _wi=$(getprop wifi.interface 2>/dev/null)
    _iface_name_ok "$_wi" || _wi=wlan0
  fi
  echo "$_wi"
  unset _wi
}

# connected | disconnected | absent
wifi_state() {
  [ -d "/sys/class/net/$1" ] || { echo absent; return 0; }
  _os=$(cat "/sys/class/net/$1/operstate" 2>/dev/null)
  case "$_os" in up) echo connected ;; *) echo disconnected ;; esac
  unset _os
}

# ── Own module flags ─────────────────────────────────────────────────────────
# Turned off or marked for removal in the root manager: everything is undone
# at once (not only at the next boot), so Wi-Fi is back to stock right away.
module_off() { [ -f "$MODDIR/disable" ] || [ -f "$MODDIR/remove" ]; }

# ── Siblings (same set) ──────────────────────────────────────────────────────
sibling_state() { # <module-id> [other id] -> absent | disabled | enabled
  _sd="$ADB/modules/$1"
  [ ! -f "$_sd/module.prop" ] && [ -n "$2" ] && _sd="$ADB/modules/$2"
  if [ ! -f "$_sd/module.prop" ]; then echo absent
  elif [ -f "$_sd/disable" ] || [ -f "$_sd/remove" ]; then echo disabled
  else echo enabled; fi
  unset _sd
}

# ── Watchdog helpers ─────────────────────────────────────────────────────────
wd_pid() {
  _wp=""
  read -r _wp 2>/dev/null < "$WD_PIDFILE"
  [ -n "$_wp" ] && kill -0 "$_wp" 2>/dev/null && echo "$_wp"
  unset _wp
}
# A settings change: the watchdog checks at once.
wake_watchdog() { _p=$(wd_pid); [ -n "$_p" ] && kill -USR1 "$_p" 2>/dev/null; unset _p; }

# ── Module status line (description in the root manager) ─────────────────────
DESC_BASE="Hides the phone on Wi-Fi networks: clean DHCP, no mDNS / SSDP / LLMNR announcements."
set_description() { # <status text>
  [ -w "$MODPROP" ] || return 0
  _dl="description=$DESC_BASE Status: $1"
  grep -qxF "$_dl" "$MODPROP" 2>/dev/null && { unset _dl; return 0; }
  _dt="$MODPROP.tmp.$$"
  { grep -v '^description=' "$MODPROP"; echo "$_dl"; } > "$_dt" 2>/dev/null && mv -f "$_dt" "$MODPROP"
  rm -f "$_dt" 2>/dev/null
  unset _dl _dt
}
