#!/system/bin/sh
# uninstall.sh - stop the watchdog and the DHCP guard, remove every rule,
# delete the data folder.
MODDIR=${0%/*}
if [ -f "$MODDIR/sh/common.sh" ] && [ -f "$MODDIR/sh/sync.sh" ]; then
  . "$MODDIR/sh/common.sh"
  . "$MODDIR/sh/dhcp.sh"
  . "$MODDIR/sh/announce.sh"
  . "$MODDIR/sh/sync.sh"
  # Stop the watchdog first and wait for it: a pass in progress would put
  # things straight back.
  _p=$(wd_pid)
  if [ -n "$_p" ]; then
    kill "$_p" 2>/dev/null
    _w=0
    while kill -0 "$_p" 2>/dev/null && [ "$_w" -lt 50 ]; do sleep 0.1 2>/dev/null || sleep 1; _w=$((_w + 1)); done
    kill -9 "$_p" 2>/dev/null
  fi
  lanc_lock
  lanc_teardown
  lanc_unlock
else
  # Library missing: by name with the plain tools
  for _p in $(pidof lanc-bpf 2>/dev/null); do kill "$_p" 2>/dev/null; done
  sleep 1
  [ -x "$MODDIR/bin/lanc-bpf" ] && "$MODDIR/bin/lanc-bpf" detach "$(getprop wifi.interface 2>/dev/null || echo wlan0)" >/dev/null 2>&1
  # shellcheck disable=SC2086,SC2046
  for _t in "iptables LANC_OUT" "ip6tables LANC_OUT6"; do
    set -- $_t
    for _r in $("$1" -w -S OUTPUT 2>/dev/null | grep -e "-j $2\$" | sed 's/^-A //; s/ /:/g'); do
      "$1" -w -D $(echo "$_r" | tr ':' ' ') 2>/dev/null
    done
    "$1" -w -F "$2" 2>/dev/null; "$1" -w -X "$2" 2>/dev/null
  done
fi
rm -rf "${LANC_DATA:-/data/adb/lan-cloak}"
