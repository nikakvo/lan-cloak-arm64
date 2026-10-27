#!/system/bin/sh
# customize.sh - installer (KernelSU / SukiSU / APatch / Magisk)
# shellcheck disable=SC2034
SKIPUNZIP=0

_V=$(sed -n 's/^version=//p' "$MODPATH/module.prop" 2>/dev/null)
ui_print " "
ui_print "******************************"
ui_print "*      LAN Cloak Arm64       *"
_bl=$(( (28 - ${#_V}) / 2 )); [ "$_bl" -lt 0 ] && _bl=0
_br=$(( 28 - ${#_V} - _bl )); [ "$_br" -lt 0 ] && _br=0
ui_print "*$(printf '%*s' "$_bl" '')$_V$(printf '%*s' "$_br" '')*"
ui_print "******************************"
ui_print "*        Tears Burn          *"
ui_print "******************************"
ui_print " "
unset _bl _br

MODDIR="$MODPATH"
LANC_BPF="$MODPATH/bin/lanc-bpf"
. "$MODPATH/sh/common.sh"

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/bin/lanc-bpf" 0 0 0755
for _f in "$MODPATH"/*.sh "$MODPATH"/sh/*.sh; do
  [ -f "$_f" ] && set_perm "$_f" 0 0 0755
done
unset _f

# ── Requirements ─────────────────────────────────────────────────────────────
ui_print "- Checking requirements"
[ "$ARCH" = arm64 ] || abort "  ! arm64 only (this device: ${ARCH:-unknown})"
[ -n "$IPT4_BIN" ] || abort "  ! iptables not found"

_IF=$(getprop wifi.interface 2>/dev/null)
_iface_name_ok "$_IF" || _IF=wlan0
ui_print "  Wi-Fi interface: $_IF"

# The DHCP cleaner is a tc eBPF program: needs BPF, clsact and cls_bpf.
_dhcp_ok=1
if [ -r /proc/config.gz ]; then
  _cfg=$(zcat /proc/config.gz 2>/dev/null)
  for _k in CONFIG_BPF_SYSCALL CONFIG_NET_CLS_BPF CONFIG_NET_SCH_INGRESS; do
    case "$_cfg" in
      *"$_k=y"* | *"$_k=m"*) ;;
      *) ui_print "  ! kernel: $_k not set"; _dhcp_ok=0 ;;
    esac
  done
  unset _cfg _k
fi
# Can this kernel load the program? (load only, nothing is attached)
_chk=$("$LANC_BPF" check "$_IF" 2>&1)
case "$_chk" in
  *ok=1*) ui_print "  DHCP cleaner: the kernel accepts it ($(uname -r))" ;;
  *)
    _dhcp_ok=0
    ui_print "  ! DHCP cleaner: the kernel refused it ($(printf '%s\n' "$_chk" | sed -n 's/^error=//p' | head -n 1) $(printf '%s\n' "$_chk" | sed -n 's/^errstr=//p' | head -n 1))" ;;
esac
unset _chk
if [ "$_dhcp_ok" = 0 ]; then
  ui_print "  ! DHCP cleaning will not work on this kernel."
  ui_print "    mDNS / SSDP / LLMNR blocking works without it."
fi

# ── Settings ─────────────────────────────────────────────────────────────────
mkdir -p "$STATE_DIR" "$LOGS_DIR" "$BACKUP_DIR"
chmod 700 "$DATA_DIR" 2>/dev/null
if [ -f "$CONF" ]; then
  ui_print "- Keeping your settings ($CONF)"
  conf_init
else
  conf_init
  if [ "$_dhcp_ok" = 0 ]; then
    conf_set DHCP_HOSTNAME 0; conf_set DHCP_VENDOR 0; conf_set DHCP_PRL 0
  fi
  ui_print "- Default settings:"
  if [ "$_dhcp_ok" = 1 ]; then
    ui_print "  DHCP: no host name, no vendor class, short request list"
  else
    ui_print "  DHCP: untouched (kernel)"
  fi
  ui_print "  Blocked on Wi-Fi: mDNS, SSDP, LLMNR"
  ui_print "  (Casting to a TV / Chromecast needs mDNS and SSDP:"
  ui_print "   turn those two off if you cast.)"
fi
unset _dhcp_ok _IF

# ── The set ──────────────────────────────────────────────────────────────────
ui_print "- Companion modules"
for _s in "dnscrypt-proxy-android:DNSCrypt Proxy Arm64" "wg-shield:WG Shield Arm64" \
          "vpn-hotspot:VPN Hotspot Arm64" "ipset_arm64:ipset-arm64"; do
  case "$(sibling_state "${_s%%:*}")" in
    enabled) ui_print "  ${_s#*:}: installed" ;;
    disabled) ui_print "  ${_s#*:}: disabled" ;;
    *) ui_print "  ${_s#*:}: not installed" ;;
  esac
done
unset _s

# ── Update in place ──────────────────────────────────────────────────────────
# A running watchdog / DHCP guard belongs to the old version and keeps
# working until the reboot; nothing is stopped here, so there is no gap.
[ -n "$(wd_pid)" ] && ui_print "- Previous version keeps running until you reboot"

ui_print " "
ui_print "- Done. Reboot to start LAN Cloak."
ui_print "  Status: su -c '/system/bin/sh /data/adb/modules/lan-cloak/ctl.sh status'"
ui_print " "
