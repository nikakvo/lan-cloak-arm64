#!/system/bin/sh
# shellcheck shell=sh disable=SC2034
#
# sh/dhcp.sh - the DHCP guard: "lanc-bpf watch <iface> <flags>" runs as a
# small daemon and keeps the DHCP cleaner (tc eBPF, egress) on the Wi-Fi
# interface. Android deletes the interface's clsact qdisc (and with it every
# filter) at every Wi-Fi off; the daemon puts it back within about half a second,
# long before the next DHCP request. These functions start, stop and check it.
# Needs sh/common.sh.

# The cleaner's flags from the settings: 1 = host name (12, 81),
# 2 = vendor class (60), 4 = parameter request list (55). 0 = guard off.
dhcp_flags_wanted() { # needs conf_load
  [ "$S_ENABLED" = 1 ] || { echo 0; return 0; }
  echo $(( S_DHCP_HOSTNAME * 1 + S_DHCP_VENDOR * 2 + S_DHCP_PRL * 4 ))
}

# pid of the running guard (empty when none). The pid file alone is not
# trusted: the process must still be "lanc-bpf watch".
guard_pid() {
  _gp=""
  read -r _gp 2>/dev/null < "$GUARD_PIDFILE"
  case "$_gp" in '' | *[!0-9]*) unset _gp; return 1 ;; esac
  if kill -0 "$_gp" 2>/dev/null && tr '\0' ' ' < "/proc/$_gp/cmdline" 2>/dev/null | grep -q 'lanc-bpf watch '; then
    echo "$_gp"; unset _gp; return 0
  fi
  unset _gp
  return 1
}

# Interface the running guard watches (argument 3 of its command line)
guard_iface() { # <pid>
  tr '\0' '\n' < "/proc/$1/cmdline" 2>/dev/null | sed -n 3p
}

# guard_start <iface> <flags> -> 0 ok; sets G_ERR on failure
guard_start() {
  G_ERR=""
  [ -x "$BPF" ] || { G_ERR="helper missing: $BPF"; return 1; }
  mkdir -p "$LOGS_DIR" "$STATE_DIR" 2>/dev/null
  tz_update
  _go=$(LANC_TZ_FILE="$TZ_FILE" LANC_PIDFILE="$GUARD_PIDFILE" "$BPF" watch "$1" "$2" "$GUARD_LOG" 2>&1)
  case "$_go" in
    *ok=1*)
      rm -f "$GUARD_FAIL"
      log_info "DHCP guard started on $1 (flags $2: $(dhcp_flags_text "$2"), pid $(printf '%s\n' "$_go" | sed -n 's/^pid=//p'))"
      unset _go
      return 0 ;;
  esac
  G_ERR=$(printf '%s\n' "$_go" | sed -n -e 's/^error=//p' | head -n 1)
  _ge=$(printf '%s\n' "$_go" | sed -n -e 's/^errstr=//p' | head -n 1)
  [ -n "$_ge" ] && G_ERR="$G_ERR ($_ge)"
  [ -n "$G_ERR" ] || G_ERR=$(printf '%s\n' "$_go" | tail -n 1)
  echo "$(date +%s) $G_ERR" > "$GUARD_FAIL"
  log_error "DHCP guard could not start on $1: $G_ERR"
  # the kernel's verifier report, if any, for the bug report
  printf '%s\n' "$_go" | grep -v -e '^ok=' -e '^error=' -e '^errno=' -e '^errstr=' | tail -n 20 |
    while read -r _gl; do [ -n "$_gl" ] && log_error "  $_gl"; done
  unset _go _ge _gl
  return 1
}

# guard_stop [iface]: SIGTERM = the daemon removes its filter and exits.
# A daemon that does not exit is killed, and the filter is removed here.
guard_stop() {
  _gp=$(guard_pid)
  _gi=${1:-}
  if [ -n "$_gp" ]; then
    [ -n "$_gi" ] || _gi=$(guard_iface "$_gp")
    kill "$_gp" 2>/dev/null
    _gw=0
    while kill -0 "$_gp" 2>/dev/null && [ "$_gw" -lt 30 ]; do
      sleep 0.1 2>/dev/null || sleep 1
      _gw=$((_gw + 1))
    done
    if kill -0 "$_gp" 2>/dev/null; then
      kill -9 "$_gp" 2>/dev/null
      log_warn "DHCP guard (pid $_gp) did not stop - killed"
    fi
    log_info "DHCP guard stopped${_gi:+ on $_gi}"
  fi
  rm -f "$GUARD_PIDFILE"
  # our filter only (pref 10, handle 1) - never Android's clsact or filters
  [ -n "$_gi" ] && [ -x "$BPF" ] && "$BPF" detach "$_gi" >/dev/null 2>&1
  unset _gp _gi _gw
}

dhcp_flags_text() { # <flags> -> "host name, vendor class, request list"
  _ft=""
  [ $(( $1 & 1 )) -ne 0 ] && _ft="host name"
  [ $(( $1 & 2 )) -ne 0 ] && _ft="${_ft:+$_ft, }vendor class"
  [ $(( $1 & 4 )) -ne 0 ] && _ft="${_ft:+$_ft, }request list"
  echo "${_ft:-nothing}"
  unset _ft
}

# Read "lanc-bpf status <iface>" into B_* variables.
guard_read() { # <iface>
  B_ATTACHED=0; B_FLAGS=""; B_SEEN=0; B_CHANGED=0; B_SKIPPED=0; B_HOST=0; B_VENDOR=0; B_PRL=0
  B_LAST_SEEN=""; B_LAST_CHANGED=""; B_PROG=""
  [ -x "$BPF" ] || return 1
  _gs=$("$BPF" status "$1" 2>/dev/null) || { unset _gs; return 1; }
  # (no here-document: mksh needs a writable temp folder for those)
  _gifs=$IFS; IFS='
'
  for _gl in $_gs; do
    _k=${_gl%%=*}; _v=${_gl#*=}
    case "$_k" in
      attached) B_ATTACHED=$_v ;;
      prog_id) B_PROG=$_v ;;
      flags) B_FLAGS=$_v ;;
      seen) B_SEEN=$_v ;;
      changed) B_CHANGED=$_v ;;
      skipped) B_SKIPPED=$_v ;;
      host) B_HOST=$_v ;;
      vendor) B_VENDOR=$_v ;;
      prl) B_PRL=$_v ;;
      last_seen_age) B_LAST_SEEN=$_v ;;
      last_changed_age) B_LAST_CHANGED=$_v ;;
    esac
  done
  IFS=$_gifs
  unset _gs _k _v _gl _gifs
  return 0
}

# dhcp_sync: the guard runs exactly when wanted, on the right interface,
# with the right flags. Sets D_STATE (on | off | waiting | error), D_IFACE,
# D_FLAGS, D_ERR. [force] = retry a failed start now.
dhcp_sync() {
  D_IFACE=$(wifi_iface)
  D_FLAGS=$(dhcp_flags_wanted)
  D_ERR=""
  module_off && D_FLAGS=0
  _dp=$(guard_pid)

  if [ "$D_FLAGS" = 0 ]; then
    [ -n "$_dp" ] && guard_stop
    [ -z "$_dp" ] && [ -x "$BPF" ] && [ -d "/sys/class/net/$D_IFACE" ] && {
      # a filter left by a killed guard (no daemon to remove it)
      guard_read "$D_IFACE" && [ "$B_ATTACHED" = 1 ] && "$BPF" detach "$D_IFACE" >/dev/null 2>&1 &&
        log_info "removed a leftover DHCP filter from $D_IFACE"
    }
    rm -f "$GUARD_FAIL"
    D_STATE=off
    unset _dp
    return 0
  fi

  # interface changed (setting or wifi.interface): move the guard
  if [ -n "$_dp" ]; then
    _di=$(guard_iface "$_dp")
    if [ "$_di" != "$D_IFACE" ]; then
      log_info "Wi-Fi interface is now $D_IFACE (was $_di) - moving the DHCP guard"
      guard_stop "$_di"
      _dp=""
    fi
  fi

  if [ -z "$_dp" ]; then
    _df=""; _dfe=""
    read -r _df _dfe 2>/dev/null < "$GUARD_FAIL"
    if [ -n "$_df" ] && [ "$1" != force ] && [ $(( $(date +%s) - _df )) -lt "$GUARD_RETRY" ]; then
      D_STATE=error; D_ERR=$_dfe
      unset _dp _di _df _dfe
      return 1
    fi
    [ -n "$_df" ] || [ ! -f "$GUARD_PIDFILE" ] || log_warn "DHCP guard was not running - starting it again"
    if ! guard_start "$D_IFACE" "$D_FLAGS"; then
      D_STATE=error; D_ERR=$G_ERR
      unset _dp _di _df _dfe
      return 1
    fi
    unset _df _dfe
  fi

  # flags changed while it runs: change them in the running program
  # (counters keep running, no gap). When that fails, restart the guard.
  if guard_read "$D_IFACE" && [ "$B_ATTACHED" = 1 ] && [ -n "$B_FLAGS" ] && [ "$B_FLAGS" != "$D_FLAGS" ]; then
    if "$BPF" set "$D_IFACE" "$D_FLAGS" >/dev/null 2>&1; then
      log_info "DHCP cleaning changed: $(dhcp_flags_text "$D_FLAGS")"
      B_FLAGS=$D_FLAGS
    else
      log_warn "could not change the DHCP flags in place - restarting the guard"
      guard_stop "$D_IFACE"
      guard_start "$D_IFACE" "$D_FLAGS" || { D_STATE=error; D_ERR=$G_ERR; unset _dp _di; return 1; }
      guard_read "$D_IFACE"
    fi
  fi

  if [ "$B_ATTACHED" = 1 ] && [ "$B_FLAGS" = "$D_FLAGS" ]; then
    D_STATE=on
  elif [ -d "/sys/class/net/$D_IFACE" ]; then
    # the guard re-attaches within ~0.5 s after Android re-creates clsact;
    # "waiting" is normal for a moment, the next tick sees it on
    D_STATE=waiting
  else
    D_STATE=waiting   # Wi-Fi interface not there (yet) - the guard waits for it
  fi
  unset _dp _di
  return 0
}
