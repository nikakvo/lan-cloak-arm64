#!/system/bin/sh
# ctl.sh - the single command-line interface. The WebUI calls only this.
# Output is key=value lines (ok=1 / ok=0 + error=...) unless noted.
#   su -c '/system/bin/sh /data/adb/modules/lan-cloak/ctl.sh help'

MODDIR="${LANC_MODDIR:-${0%/*}}"
[ -f "$MODDIR/sh/common.sh" ] || MODDIR=/data/adb/modules/lan-cloak
. "$MODDIR/sh/common.sh"
. "$MODDIR/sh/dhcp.sh"
. "$MODDIR/sh/announce.sh"
. "$MODDIR/sh/sync.sh"

fail() { echo "ok=0"; echo "error=$*"; exit 1; }

[ "$(id -u)" = 0 ] || fail "run as root: su -c '/system/bin/sh /data/adb/modules/lan-cloak/ctl.sh $*'"
mkdir -p "$STATE_DIR" "$LOGS_DIR" 2>/dev/null

_watchdog_rows() {
  _wp=$(wd_pid)
  echo "watchdog=$([ -n "$_wp" ] && echo running || echo stopped)"
  _tk=""; read -r _tk 2>/dev/null < "$TICK_FILE"
  if [ -n "$_tk" ]; then echo "tick_age=$(( $(date +%s) - _tk ))"; else echo "tick_age="; fi
  _since=""; read -r _since _ss 2>/dev/null < "$SINCE_FILE"
  echo "since=$_since"
  unset _wp _tk _since _ss
}

# The set: installed / disabled / absent, plus each one's own state from
# its status file (new path first, then the old one).
_sib_val() { # <key> <file> [old file]
  _sf=$2; [ -f "$_sf" ] || _sf=${3:-$2}
  sed -n "s/^$1=//p" "$_sf" 2>/dev/null | head -n 1
  unset _sf
}
_sibling_rows() {
  echo "dnscrypt=$(sibling_state dnscrypt-proxy-android)"
  echo "dnscrypt_state=$(_sib_val state "$ADB/dnscrypt-proxy/state/health" "$ADB/dnscrypt-proxy-state/health")"
  echo "wgshield=$(sibling_state wg-shield)"
  echo "wgshield_state=$(_sib_val state "$ADB/wg-shield/state/status" "$ADB/wg-shield-state/status")"
  echo "wgshield_tunnel=$(_sib_val tunnel "$ADB/wg-shield/state/status" "$ADB/wg-shield-state/status")"
  echo "vpnhotspot=$(sibling_state vpn-hotspot)"
  echo "vpnhotspot_state=$(_sib_val state "$ADB/vpn-hotspot/state/status" "$ADB/vpn-hotspot-state/status")"
  echo "ipset=$(sibling_state ipset_arm64 ipset-arm64)"
}

# Fresh pass (checks the tables, the guard), then everything as key=value.
cmd_status() {
  lanc_lock; lanc_sync; lanc_unlock
  echo "ok=1"
  cat "$STATUS_FILE" 2>/dev/null
  for _k in $SETTINGS_KEYS; do echo "set_$_k=$(conf_get "$_k")"; done
  _watchdog_rows
  _sibling_rows
  unset _k
}

# Cheap snapshot for the WebUI, polled every few seconds: files only (the
# watchdog's last pass + settings). No iptables, no netlink.
cmd_poll() {
  echo "ok=1"
  cat "$STATUS_FILE" 2>/dev/null
  conf_load
  for _k in $SETTINGS_KEYS; do eval "echo \"set_$_k=\$S_$_k\""; done
  echo "now=$(date +%s)"
  _watchdog_rows
  _sibling_rows
  unset _k
}

cmd_set() { # <KEY> <value>
  [ -n "$1" ] || fail "usage: set KEY VALUE"
  case " $SETTINGS_KEYS " in *" $1 "*) ;; *) fail "unknown setting: $1" ;; esac
  conf_valid "$1" "$2" || fail "invalid value for $1: $2"
  _old=$(conf_get "$1")
  conf_set "$1" "$2" || fail "cannot write $CONF"
  [ "$_old" != "$2" ] && log_info "setting $1: $_old -> $2"
  lanc_lock; lanc_sync force; lanc_unlock
  echo "ok=1"
  echo "$1=$2"
  echo "state=$L_STATE"
  echo "dhcp=$D_STATE"
  echo "announce=$A_STATE"
  [ -n "$D_ERR" ] && echo "dhcp_error=$D_ERR"
  unset _old
}

_tail_log() { # <file> <arg>
  case "$2" in
    clear)
      if log_clear "$1" 2>/dev/null; then echo "ok=1"; else fail "cannot write $1"; fi ;;
    '') tail -n 50 "$1" 2>/dev/null ;;
    *[!0-9]*) fail "log takes a number of lines or clear" ;;
    *) tail -n "$2" "$1" 2>/dev/null ;;
  esac
}

cmd_diag() { # everything needed for a bug report, plain text
  echo "== status"; cmd_status
  echo "== settings"; cat "$CONF" 2>/dev/null
  _di=$(wifi_iface)
  echo "== wifi.interface"; getprop wifi.interface 2>&1
  echo "== DHCP guard ($BPF)"; "$BPF" version 2>&1; "$BPF" status "$_di" 2>&1
  echo "== tc qdisc $_di"; tc qdisc show dev "$_di" 2>&1
  echo "== tc filter $_di egress"; tc filter show dev "$_di" egress 2>&1
  echo "== OUTPUT"; iptables -S OUTPUT 2>&1
  echo "== $C_OUT"; iptables -L "$C_OUT" -v -n 2>&1
  echo "== ip6 OUTPUT"; ip6tables -S OUTPUT 2>&1
  echo "== $C_OUT6"; ip6tables -L "$C_OUT6" -v -n 2>&1
  echo "== kernel"; uname -r 2>&1
  echo "== log"; tail -n 60 "$LOG" 2>/dev/null
  echo "== guard log"; tail -n 60 "$GUARD_LOG" 2>/dev/null
  unset _di
}

cmd_help() {
  cat <<'EOF'
LAN Cloak Arm64 - ctl.sh
  su -c '/system/bin/sh /data/adb/modules/lan-cloak/ctl.sh <command>'

  status              state, DHCP guard, firewall rules, settings (fresh check)
  set KEY VALUE       change a setting (applied at once)
      ENABLED 0|1          everything on / off
      DHCP_HOSTNAME 0|1    remove the device name from DHCP (options 12, 81)
      DHCP_VENDOR 0|1      remove "android-dhcp-NN" from DHCP (option 60)
      DHCP_PRL 0|1         short, common parameter request list (option 55)
      BLOCK_MDNS 0|1       block mDNS (stops casting / device discovery)
      BLOCK_SSDP 0|1       block SSDP / UPnP discovery
      BLOCK_LLMNR 0|1      block LLMNR name lookups
      WIFI_IFACE auto|<if> Wi-Fi interface (auto = Android's wifi.interface)
  dhcp                the DHCP cleaner's own report and counters
  sync [force]        check and repair now (force: retry a failed DHCP guard)
  wifi-restart        Wi-Fi off and on: a new DHCP request right away
  log [N|clear]       last N lines of the module log (default 50)
  guardlog [N|clear]  last N lines of the DHCP guard log (Wi-Fi events)
  diag                full report for troubleshooting
  version
EOF
}

case "$1" in
  status) cmd_status ;;
  poll) cmd_poll ;;
  set) shift; cmd_set "$1" "$2" ;;
  dhcp) "$BPF" status "$(wifi_iface)" ;;
  sync)
    lanc_lock
    if [ "$2" = force ]; then lanc_sync force; else lanc_sync; fi
    lanc_unlock
    echo "ok=1"; cat "$STATUS_FILE" 2>/dev/null ;;
  log) _tail_log "$LOG" "$2" ;;
  guardlog) _tail_log "$GUARD_LOG" "$2" ;;
  diag) cmd_diag ;;
  wifi-restart)
    # Wi-Fi off and on again: Android sends a new DHCP request at once (and
    # every app that announces itself starts again) - the quickest way to
    # see the current settings at work.
    command -v cmd >/dev/null 2>&1 || fail "the cmd tool is missing"
    cmd wifi set-wifi-enabled disabled >/dev/null 2>&1 || fail "Android refused to switch Wi-Fi off"
    sleep 2
    cmd wifi set-wifi-enabled enabled >/dev/null 2>&1 || fail "Wi-Fi was switched off but not back on - switch it on by hand"
    log_info "Wi-Fi restarted from the WebUI / ctl.sh"
    echo "ok=1" ;;
  version) echo "version=$(sed -n 's/^version=//p' "$MODPROP" 2>/dev/null)"; "$BPF" version 2>/dev/null; echo "ok=1" ;;
  help | -h | --help | "") cmd_help ;;
  *) fail "unknown command: $1" ;;
esac
