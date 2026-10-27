#!/system/bin/sh
# shellcheck shell=sh disable=SC2034
#
# sh/sync.sh - one pass: DHCP guard + announcement rules as the settings
# say, then the status file and the manager's description line.
# Needs sh/common.sh, sh/dhcp.sh, sh/announce.sh. Call under lanc_lock.

APPLIED_FILE="$STATE_DIR/applied"   # what the firewall pass last applied
NAME_FILE="$STATE_DIR/devname"       # <epoch> <device name> (looked up at most every 5 min)

# What Android would put into DHCP without the module, for the WebUI's
# "seen by the router" view. Host name: the device name (Settings > About
# phone) made DNS-safe the way Android's NetworkStack does it (every
# character outside A-Z a-z 0-9 - becomes "-", at most 63). Vendor class:
# "android-dhcp-" + the Android version.
device_name() {
  _nn=""; _na=""
  read -r _na _nn 2>/dev/null < "$NAME_FILE"
  _nw=$(date +%s)
  case "$_na" in '' | *[!0-9]*) _na=0 ;; esac
  if [ -z "$_nn" ] || [ $((_nw - _na)) -ge 300 ] || [ "$_nw" -lt "$_na" ]; then
    _nv=""
    if [ "$(getprop sys.boot_completed 2>/dev/null)" = 1 ] && command -v settings >/dev/null 2>&1; then
      _nv=$(settings get global device_name 2>/dev/null | head -n 1)
      [ "$_nv" = null ] && _nv=""
    fi
    [ -n "$_nv" ] || _nv=$(getprop persist.sys.device_name 2>/dev/null)
    [ -n "$_nv" ] || _nv=$(getprop ro.product.model 2>/dev/null)
    if [ -n "$_nv" ]; then _nn=$_nv; echo "$_nw $_nn" > "$NAME_FILE" 2>/dev/null; fi
  fi
  echo "$_nn"
  unset _nn _na _nw _nv
}
dhcp_name_of() { # <device name> -> host name as Android sends it
  printf '%s' "$1" | tr -c 'A-Za-z0-9-' '-' | sed 's/^-*//; s/-*$//' | cut -c 1-63
}
# Locally administered MAC (second hex digit 2 6 A E, also 3 7 B F) =
# randomized by Android; otherwise the factory address.
mac_random() {
  case "$1" in ?[2367abefABEF]:*) echo 1 ;; ?*) echo 0 ;; *) echo "" ;; esac
}

# lanc_sync [force]   (force = retry a failed DHCP guard start now)
lanc_sync() {
  conf_load
  _prev=""; _ps=""; read -r _ps _prev 2>/dev/null < "$SINCE_FILE"
  # written at early boot with the clock still at 1970: correct it once
  if [ -n "$_ps" ] && [ "$_ps" -lt 1577836800 ] 2>/dev/null && clock_ok; then
    echo "$(date +%s) $_prev" > "$SINCE_FILE"
  fi

  dhcp_sync "$1"
  announce_sync

  # a repair (not the first apply after a change) is worth a line in the log
  _sig="$(wifi_iface) $S_ENABLED $S_BLOCK_MDNS $S_BLOCK_SSDP $S_BLOCK_LLMNR"
  _was=""; read -r _was 2>/dev/null < "$APPLIED_FILE"
  if [ "$A_STATE" = on ]; then
    if [ "$_was" != "$_sig" ]; then
      log_info "announcements blocked on $(wifi_iface): $(announce_text)$([ "$A_V6" = 1 ] || echo ' (IPv4 only - no ip6tables)')"
    elif [ -n "$A_PROBLEM" ]; then
      log_warn "firewall rules repaired ($A_PROBLEM)"
    fi
    echo "$_sig" > "$APPLIED_FILE"
  elif [ "$A_STATE" = off ]; then
    rm -f "$APPLIED_FILE"
  fi

  # overall state
  _reason=""
  if module_off; then L_STATE=off; _reason=module-disabled
  elif [ "$S_ENABLED" != 1 ]; then L_STATE=off; _reason=disabled
  elif [ "$D_STATE" = error ]; then L_STATE=error; _reason=dhcp
  elif [ "$A_STATE" = error ]; then L_STATE=error; _reason=firewall
  elif [ "$D_STATE" = off ] && [ "$A_STATE" = off ]; then L_STATE=off; _reason=nothing-selected
  else L_STATE=on
  fi

  status_write "$_reason"

  if [ "$_prev" != "$L_STATE" ]; then
    echo "$(date +%s) $L_STATE" > "$SINCE_FILE"
    case "$L_STATE" in
      on) log_info "LAN Cloak on ($(wifi_iface)): DHCP $( [ "$D_STATE" = off ] && echo untouched || echo "cleaned - $(dhcp_flags_text "$D_FLAGS")"), blocked: $(announce_text)" ;;
      off) [ -n "$_prev" ] && log_info "LAN Cloak off ($_reason)" ;;
      error) if [ "$_reason" = dhcp ]; then log_warn "LAN Cloak: DHCP guard failed${D_ERR:+: $D_ERR} (announcements are still blocked)"
             else log_warn "LAN Cloak: firewall rules could not be set"; fi ;;
    esac
  fi
  desc_update "$_reason"
  unset _prev _ps _sig _was _reason
}

status_write() { # <reason>
  _now=$(date +%s)
  _gp=$(guard_pid)
  [ "$D_STATE" = off ] || guard_read "$D_IFACE" >/dev/null 2>&1
  _dn=$(device_name)
  _mac=$(cat "/sys/class/net/$D_IFACE/address" 2>/dev/null)
  _ip4=$(ip -4 -o addr show dev "$D_IFACE" 2>/dev/null | sed -n 's/.* inet \([0-9.]*\/[0-9]*\) .*/\1/p' | head -n 1)
  _lsc=""; _lss=""
  # the helper gives ages in seconds; the status keeps the age at "updated"
  # and the moment itself (epoch), so a reader can count on from there
  [ -n "$B_LAST_CHANGED" ] && _lsc=$((_now - B_LAST_CHANGED))
  [ -n "$B_LAST_SEEN" ] && _lss=$((_now - B_LAST_SEEN))
  {
    echo "state=$L_STATE"
    echo "reason=$1"
    echo "version=$(sed -n 's/^version=//p' "$MODPROP" 2>/dev/null)"
    echo "iface=$D_IFACE"
    echo "wifi=$(wifi_state "$D_IFACE")"
    echo "dhcp=$D_STATE"
    echo "dhcp_flags=$D_FLAGS"
    echo "dhcp_guard=$([ -n "$_gp" ] && echo running || echo stopped)"
    echo "dhcp_guard_pid=$_gp"
    echo "dhcp_attached=${B_ATTACHED:-0}"
    echo "dhcp_error=$D_ERR"
    if [ "$D_STATE" != off ]; then
      echo "dhcp_seen=$B_SEEN"
      echo "dhcp_changed=$B_CHANGED"
      echo "dhcp_skipped=$B_SKIPPED"
      echo "dhcp_n_host=$B_HOST"
      echo "dhcp_n_vendor=$B_VENDOR"
      echo "dhcp_n_prl=$B_PRL"
      echo "dhcp_last_seen=$B_LAST_SEEN"
      echo "dhcp_last_changed=$B_LAST_CHANGED"
      echo "dhcp_last_seen_at=$_lss"
      echo "dhcp_last_changed_at=$_lsc"
    fi
    echo "wifi_mac=$_mac"
    echo "wifi_mac_random=$(mac_random "$_mac")"
    echo "wifi_ipv4=$_ip4"
    echo "device_name=$_dn"
    echo "android_hostname=$(dhcp_name_of "$_dn")"
    echo "android_vendor=android-dhcp-$(getprop ro.build.version.release 2>/dev/null)"
    echo "announce=$A_STATE"
    echo "announce_ipv6=$A_V6"
    echo "block_mdns=$( [ "$A_STATE" = on ] && echo "$S_BLOCK_MDNS" || echo 0)"
    echo "block_ssdp=$( [ "$A_STATE" = on ] && echo "$S_BLOCK_SSDP" || echo 0)"
    echo "block_llmnr=$( [ "$A_STATE" = on ] && echo "$S_BLOCK_LLMNR" || echo 0)"
    echo "blocked_mdns=${A_N_MDNS:-0}"
    echo "blocked_ssdp=${A_N_SSDP:-0}"
    echo "blocked_llmnr=${A_N_LLMNR:-0}"
    echo "updated=$_now"
  } > "$STATUS_FILE.tmp.$$" 2>/dev/null && mv -f "$STATUS_FILE.tmp.$$" "$STATUS_FILE"
  rm -f "$STATUS_FILE.tmp.$$" 2>/dev/null
  unset _now _gp _lsc _lss _dn _mac _ip4
}

desc_update() { # <reason>
  case "$L_STATE" in
    on)
      _dd="DHCP clean"; [ "$D_STATE" = off ] && _dd="DHCP untouched"
      _da=""; [ "$A_STATE" = on ] && _da=" · $(announce_text) blocked"
      set_description "🟢 Active on $D_IFACE · $_dd$_da" ;;
    error)
      if [ "$1" = dhcp ]; then set_description "⚠️ DHCP guard failed: ${D_ERR:-see log}"
      else set_description "⚠️ Firewall rules failed - see log"; fi ;;
    *)
      case "$1" in
        module-disabled) set_description "⏸️ Disabled in the manager" ;;
        nothing-selected) set_description "⚪ Nothing selected" ;;
        *) set_description "⚪ Off" ;;
      esac ;;
  esac
  unset _dd _da
}

# Undo everything (uninstall, module turned off)
lanc_teardown() {
  _ti=$(wifi_iface)
  guard_stop
  [ -x "$BPF" ] && [ -d "/sys/class/net/$_ti" ] && "$BPF" detach "$_ti" >/dev/null 2>&1
  announce_teardown
  rm -f "$APPLIED_FILE"
  unset _ti
}
