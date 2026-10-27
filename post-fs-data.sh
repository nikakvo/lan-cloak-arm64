#!/system/bin/sh
# post-fs-data.sh - early boot, before Wi-Fi starts.
# Clears the previous boot's runtime state and starts the DHCP guard NOW:
# the first DHCP request after boot must already be clean. The guard waits
# for the Wi-Fi interface by itself. The firewall rules are set here too
# (and kept by the watchdog, service.sh, after netd has set up its chains).
MODDIR=${0%/*}
[ -f "$MODDIR/sh/common.sh" ] || exit 0
. "$MODDIR/sh/common.sh"
. "$MODDIR/sh/dhcp.sh"
. "$MODDIR/sh/announce.sh"
. "$MODDIR/sh/sync.sh"
mkdir -p "$STATE_DIR" "$LOGS_DIR" "$BACKUP_DIR"
chmod 700 "$DATA_DIR" 2>/dev/null
rm -rf "$LOCK_DIR"
rm -f "$WD_PIDFILE" "$TICK_FILE" "$STATUS_FILE" "$SINCE_FILE" "$GUARD_PIDFILE" "$GUARD_FAIL" \
      "$IPT_WAIT_FILE" "$IPTR_WAIT_FILE" "$STATE_DIR/applied" "$TZ_FILE" "$STATE_DIR/devname"
conf_init
log_trim
log_trim "$GUARD_LOG"
log_info "boot: $(sed -n 's/^version=//p' "$MODPROP" 2>/dev/null), Wi-Fi interface $(wifi_iface)"
module_off && exit 0
lanc_lock
lanc_sync
lanc_unlock
exit 0
