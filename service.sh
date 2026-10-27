#!/system/bin/sh
# service.sh - the watchdog.
#
# The DHCP guard (lanc-bpf watch) reacts to Wi-Fi events by itself. The
# watchdog only keeps everything in line with the settings: the guard runs
# (on the right interface, with the right flags), the firewall rules are
# there (netd or another module may flush or reorder OUTPUT), the status
# file is fresh, the logs stay small. Faster ticks right after boot, while
# netd builds its own chains.

MODDIR=${0%/*}
. "$MODDIR/sh/common.sh"
. "$MODDIR/sh/dhcp.sh"
. "$MODDIR/sh/announce.sh"
. "$MODDIR/sh/sync.sh"

mkdir -p "$STATE_DIR" "$LOGS_DIR"
conf_init

# One watchdog only
_old=$(wd_pid)
if [ -n "$_old" ] && [ "$_old" != "$$" ]; then
  log_warn "watchdog already running (pid $_old) - not starting another"
  exit 0
fi
echo "$$" > "$WD_PIDFILE"
log_info "watchdog started (pid $$, tick ${TICK}s)"

WAKE=0
trap 'WAKE=1' USR1
_wd_exit() {
  _lo=""; read -r _lo 2>/dev/null < "$LOCK_DIR/pid"
  [ "$_lo" = "$$" ] && lanc_unlock
  rm -f "$WD_PIDFILE"
  log_info "watchdog stopped"
  exit 0
}
trap '_wd_exit' TERM INT HUP

_t0=$(date +%s)
_n=0
_was_off=""
while :; do
  WAKE=0
  # Reboot / power off: netd and iptables are going away - nothing to keep
  if shutting_down; then
    log_info "phone is shutting down - watchdog stops"
    rm -f "$WD_PIDFILE"
    exit 0
  fi
  tz_update
  lanc_lock
  if module_off; then
    # turned off / marked for removal in the root manager: undo at once
    if [ "$_was_off" != 1 ]; then
      lanc_teardown
      log_info "module disabled in the root manager - DHCP guard and rules removed"
      _was_off=1
    fi
  else
    [ "$_was_off" = 1 ] && log_info "module enabled again in the root manager"
    _was_off=0
  fi
  lanc_sync
  lanc_unlock
  date +%s > "$TICK_FILE"

  _n=$((_n + 1))
  if [ $((_n % 30)) -eq 0 ]; then log_trim; log_trim "$GUARD_LOG"; fi

  _t=$TICK
  [ $(( $(date +%s) - _t0 )) -lt "$BOOT_FAST" ] && _t=$TICK_BOOT
  sleep "$_t" &
  _sp=$!
  wait "$_sp" 2>/dev/null
  kill "$_sp" 2>/dev/null
done
