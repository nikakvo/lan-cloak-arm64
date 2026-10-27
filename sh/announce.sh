#!/system/bin/sh
# shellcheck shell=sh disable=SC2034
#
# sh/announce.sh - blocks the phone's LAN announcements on Wi-Fi:
#   mDNS   224.0.0.251 / ff02::fb  udp 5353   (Xiaomi HyperConnect, cast and
#          media apps announce themselves and look for devices)
#   SSDP   239.255.255.250 / ff02::c / ff05::c  udp 1900   (UPnP discovery)
#   LLMNR  224.0.0.252 / ff02::1:3 (and any multicast) udp 5355   (name lookups)
# plus the unicast answers the phone would send from those ports.
#
# filter OUTPUT gets ONE jump per family, APPENDED (after everything netd and
# the sibling modules put there) and only for the Wi-Fi interface:
#   -A OUTPUT -o wlan0 -j LANC_OUT     /    -A OUTPUT -o wlan0 -j LANC_OUT6
# The chains only DROP; they never ACCEPT, so nothing of anyone else's is
# skipped. Hotspot interfaces and mobile data are not matched.
# Needs sh/common.sh.

# Expected chain contents, exactly as iptables-save prints them (the check
# compares text). Needs conf_load.
announce_rules4() {
  if [ "$S_BLOCK_MDNS" = 1 ]; then
    echo "-A $C_OUT -d 224.0.0.251/32 -p udp -m udp --dport 5353 -j DROP"
    echo "-A $C_OUT -p udp -m udp --sport 5353 -j DROP"
  fi
  if [ "$S_BLOCK_SSDP" = 1 ]; then
    echo "-A $C_OUT -d 239.255.255.250/32 -p udp -m udp --dport 1900 -j DROP"
    echo "-A $C_OUT -p udp -m udp --sport 1900 -j DROP"
  fi
  if [ "$S_BLOCK_LLMNR" = 1 ]; then
    echo "-A $C_OUT -d 224.0.0.0/4 -p udp -m udp --dport 5355 -j DROP"
    echo "-A $C_OUT -p udp -m udp --sport 5355 -j DROP"
    echo "-A $C_OUT -p tcp -m tcp --sport 5355 -j DROP"
  fi
}

announce_rules6() {
  if [ "$S_BLOCK_MDNS" = 1 ]; then
    echo "-A $C_OUT6 -d ff02::fb/128 -p udp -m udp --dport 5353 -j DROP"
    echo "-A $C_OUT6 -p udp -m udp --sport 5353 -j DROP"
  fi
  if [ "$S_BLOCK_SSDP" = 1 ]; then
    echo "-A $C_OUT6 -d ff02::c/128 -p udp -m udp --dport 1900 -j DROP"
    echo "-A $C_OUT6 -d ff05::c/128 -p udp -m udp --dport 1900 -j DROP"
    echo "-A $C_OUT6 -p udp -m udp --sport 1900 -j DROP"
  fi
  if [ "$S_BLOCK_LLMNR" = 1 ]; then
    echo "-A $C_OUT6 -d ff00::/8 -p udp -m udp --dport 5355 -j DROP"
    echo "-A $C_OUT6 -p udp -m udp --sport 5355 -j DROP"
    echo "-A $C_OUT6 -p tcp -m tcp --sport 5355 -j DROP"
  fi
}

# Is anything to block at all? (needs conf_load)
announce_wanted() {
  [ "$S_ENABLED" = 1 ] || return 1
  module_off && return 1
  [ "$S_BLOCK_MDNS" = 1 ] || [ "$S_BLOCK_SSDP" = 1 ] || [ "$S_BLOCK_LLMNR" = 1 ]
}

# _ann_check <4|6> <dump> <chain> <iface> <expected rules>
# -> "" when everything is in place, else a short reason
_ann_check() {
  _cd=$2; _cc=$3; _ci=$4; _ce=$5
  _have=$(printf '%s\n' "$_cd" | grep -e "^-A $_cc " || true)
  if ! printf '%s\n' "$_cd" | grep -qx -e "-N $_cc"; then echo "chain $_cc missing"
  elif [ "$_have" != "$_ce" ]; then echo "chain $_cc changed"
  else
    _jn=$(printf '%s\n' "$_cd" | grep -c -e "^-A OUTPUT .*-j $_cc\$")
    if [ "$_jn" != 1 ]; then echo "jump to $_cc: $_jn"
    elif ! printf '%s\n' "$_cd" | grep -qx -e "-A OUTPUT -o $_ci -j $_cc"; then echo "jump to $_cc: wrong interface"
    fi
  fi
  unset _cd _cc _ci _ce _have _jn
}

# _ann_apply <4|6> <dump> <chain> <iface> <expected rules>
# Rebuilds the chain (one iptables-restore) and makes sure exactly one jump
# for <iface> exists, appended to OUTPUT.
_ann_apply() {
  _af=$1; _ad=$2; _ac=$3; _ai=$4; _ae=$5
  if [ "$_af" = 6 ]; then _at=ip6tables; else _at=iptables; fi
  # Keep one correct jump (no gap while only the chain is rebuilt); stale
  # ones (other interface, duplicates) are deleted.
  _ok=0
  _jumps=$(printf '%s\n' "$_ad" | grep -e "^-A OUTPUT .*-j $_ac\$")
  _aifs=$IFS; IFS='
'
  for _al in $_jumps; do
    if [ "$_ok" = 0 ] && [ "$_al" = "-A OUTPUT -o $_ai -j $_ac" ]; then _ok=1; continue; fi
    IFS=$_aifs
    # shellcheck disable=SC2086
    $_at -D ${_al#-A } 2>/dev/null
    IFS='
'
  done
  IFS=$_aifs
  {
    echo "*filter"
    echo ":$_ac - [0:0]"
    printf '%s\n' "$_ae"
    [ "$_ok" = 1 ] || echo "-A OUTPUT -o $_ai -j $_ac"
    echo "COMMIT"
  } | ipt_restore "$_af" 2>/dev/null
  _ar=$?
  unset _af _ad _ac _ai _ae _at _al _ok _jumps _aifs
  return $_ar
}

_ann_remove() { # <4|6> <dump> <chain>
  if [ "$1" = 6 ]; then _at=ip6tables; else _at=iptables; fi
  printf '%s\n' "$2" | grep -e "^-A OUTPUT .*-j $3\$" | sed 's/^-A /-D /' |
    while read -r _al; do
      # shellcheck disable=SC2086
      $_at $_al 2>/dev/null
    done
  if printf '%s\n' "$2" | grep -qx -e "-N $3"; then
    $_at -F "$3" 2>/dev/null
    $_at -X "$3" 2>/dev/null
  fi
  unset _at _al
}

# announce_sync: rules exactly as the settings say. Sets A_STATE
# (on | off | error), A_V6 (1 = IPv6 rules too), A_PROBLEM (what was repaired).
announce_sync() {
  A_PROBLEM=""; A_V6=0; A_N_MDNS=0; A_N_SSDP=0; A_N_LLMNR=0
  _sif=$(wifi_iface)
  _d4=$(ipt_dump 4 filter) || { A_STATE=error; A_PROBLEM="cannot read iptables"; unset _sif _d4; return 1; }
  _d6=""; _v6=0
  if [ -n "$IPT6_BIN" ] && _d6=$(ipt_dump 6 filter); then _v6=1; fi

  if ! announce_wanted; then
    case "$_d4" in *"$C_OUT"*) _ann_remove 4 "$_d4" "$C_OUT"; log_info "announcement blocking removed" ;; esac
    [ "$_v6" = 1 ] && case "$_d6" in *"$C_OUT6"*) _ann_remove 6 "$_d6" "$C_OUT6" ;; esac
    A_STATE=off
    unset _sif _d4 _d6 _v6
    return 0
  fi

  A_STATE=on
  _ann_count "$_d4"
  [ "$_v6" = 1 ] && _ann_count "$_d6"
  _e4=$(announce_rules4)
  _p4=$(_ann_check 4 "$_d4" "$C_OUT" "$_sif" "$_e4")
  if [ -n "$_p4" ]; then
    A_PROBLEM=$_p4
    if ! _ann_apply 4 "$_d4" "$C_OUT" "$_sif" "$_e4"; then
      A_STATE=error; log_error "could not set the IPv4 announcement rules ($_p4)"
    fi
  fi
  if [ "$_v6" = 1 ]; then
    A_V6=1
    _e6=$(announce_rules6)
    _p6=$(_ann_check 6 "$_d6" "$C_OUT6" "$_sif" "$_e6")
    if [ -n "$_p6" ]; then
      A_PROBLEM="${A_PROBLEM:+$A_PROBLEM, }$_p6"
      if ! _ann_apply 6 "$_d6" "$C_OUT6" "$_sif" "$_e6"; then
        A_STATE=error; log_error "could not set the IPv6 announcement rules ($_p6)"
      fi
    fi
  fi
  unset _sif _d4 _d6 _v6 _e4 _e6 _p4 _p6
  [ "$A_STATE" != error ]
}

# Packets the rules dropped (iptables counters, from ipt_dump's "#C
# <packets> <port>" lines). Since the rules were set: a boot or a settings
# change starts again at 0.
_ann_count() { # <dump>
  _cls=$(printf '%s\n' "$1" | sed -n 's/^#C \([0-9][0-9]* [0-9][0-9]*\)$/\1/p')
  _cifs=$IFS; IFS='
'
  for _cl in $_cls; do
    _cn=${_cl%% *}
    case "$_cn" in '' | *[!0-9]*) continue ;; esac
    case "${_cl#* }" in
      5353) A_N_MDNS=$((A_N_MDNS + _cn)) ;;
      1900) A_N_SSDP=$((A_N_SSDP + _cn)) ;;
      5355) A_N_LLMNR=$((A_N_LLMNR + _cn)) ;;
    esac
  done
  IFS=$_cifs
  unset _cifs _cl _cn _cls
}

announce_teardown() {
  _d4=$(ipt_dump 4 filter) && _ann_remove 4 "$_d4" "$C_OUT"
  [ -n "$IPT6_BIN" ] && _d6=$(ipt_dump 6 filter) && _ann_remove 6 "$_d6" "$C_OUT6"
  unset _d4 _d6
}

# What is blocked, for the log / status
announce_text() { # needs conf_load
  _tx=""
  [ "$S_BLOCK_MDNS" = 1 ] && _tx="mDNS"
  [ "$S_BLOCK_SSDP" = 1 ] && _tx="${_tx:+$_tx, }SSDP"
  [ "$S_BLOCK_LLMNR" = 1 ] && _tx="${_tx:+$_tx, }LLMNR"
  echo "${_tx:-nothing}"
  unset _tx
}
