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
# filter OUTPUT gets ONE jump per family, APPENDED and only for the Wi-Fi
# interface:
#   -A OUTPUT -o wlan0 -j LANC_OUT     /    -A OUTPUT -o wlan0 -j LANC_OUT6
# It is set at post-fs-data, so on a phone it ends up AFTER the chains that
# were there by then (the sibling modules) and BEFORE the ones netd appends
# later (oem_out, fw_OUTPUT, bw_OUTPUT ...). Either order is fine: the
# chains only DROP and never ACCEPT, so nothing of anyone else's is skipped.
# Hotspot interfaces and mobile data are not matched.
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

# _ann_expect: A_E4 / A_E6 = the expected chains (newline-separated), built
# once per settings combination (needs conf_load).
_ann_expect() {
  _ek="$S_BLOCK_MDNS$S_BLOCK_SSDP$S_BLOCK_LLMNR"
  [ "$_ek" = "$_A_EKEY" ] && { unset _ek; return 0; }
  A_E4=$(announce_rules4); A_E6=$(announce_rules6); _A_EKEY=$_ek
  unset _ek
}

# Is anything to block at all? (needs conf_load)
announce_wanted() {
  [ "$S_ENABLED" = 1 ] || return 1
  module_off && return 1
  [ "$S_BLOCK_MDNS" = 1 ] || [ "$S_BLOCK_SSDP" = 1 ] || [ "$S_BLOCK_LLMNR" = 1 ]
}

# _ann_check <dump> <chain> <iface> <expected rules>
# -> A_CHK = "" when everything is in place, else a short reason. Adds the
# chain's "#C" packet counts to A_N_*. One pass over the (short, see
# ipt_chain) dump in the shell itself: no tool, no subshell.
_ann_check() {
  _cn=0; _have=""; _jn=0; _jok=0
  _cifs=$IFS; IFS=$NL
  set -f
  for _cl in $1; do
    case "$_cl" in
      "-N $2") _cn=1 ;;
      "-A $2 "*) _have="${_have:+$_have$NL}$_cl" ;;
      "-A OUTPUT "*"-j $2")
        _jn=$((_jn + 1))
        [ "$_cl" = "-A OUTPUT -o $3 -j $2" ] && _jok=1 ;;
      "#C "*)
        _cp=${_cl#"#C "}; _cv=${_cp%% *}
        case "$_cv" in '' | *[!0-9]*) continue ;; esac
        case "${_cp#* }" in
          5353) A_N_MDNS=$((A_N_MDNS + _cv)) ;;
          1900) A_N_SSDP=$((A_N_SSDP + _cv)) ;;
          5355) A_N_LLMNR=$((A_N_LLMNR + _cv)) ;;
        esac ;;
    esac
  done
  set +f
  IFS=$_cifs
  if [ "$_cn" != 1 ]; then A_CHK="chain $2 missing"
  elif [ "$_have" != "$4" ]; then A_CHK="chain $2 changed"
  elif [ "$_jn" != 1 ]; then A_CHK="jump to $2: $_jn"
  elif [ "$_jok" != 1 ]; then A_CHK="jump to $2: wrong interface"
  else A_CHK=""
  fi
  unset _cn _have _jn _jok _cifs _cl _cp _cv
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
# (on | off | error | keep), A_V6 (1 = IPv6 rules too), A_PROBLEM (what was
# repaired), A_N_* (blocked packets: iptables counters, from ipt_chain's
# "#C <packets> <port>" lines; since the rules were set, so a boot or a
# settings change starts again at 0).
#
# A table that cannot be READ says nothing about the rules: it happens in
# the last second of a shutdown (iptables-save fails before sys.powerctl
# is set). Then A_STATE=keep - this pass changes nothing and reports
# nothing (lanc_sync keeps the last status). Only the second failed read in
# a row in the same process (the watchdog: 20 s later) is an error - so the
# status is never older than the 60 s after which the siblings call it stale.
announce_sync() {
  A_PROBLEM=""; A_V6=0; A_N_MDNS=0; A_N_SSDP=0; A_N_LLMNR=0
  _sif=$W_IF
  if ! ipt_chain 4 "$C_OUT"; then
    _A_RF=$(( ${_A_RF:-0} + 1 ))
    if [ "$_A_RF" -ge 2 ] && ! shutting_down_any; then
      A_STATE=error; A_PROBLEM="cannot read iptables"
      [ "$_A_RF" = 2 ] && log_error "cannot read the firewall tables (iptables-save failed twice in a row)"
      unset _sif; return 1
    fi
    A_STATE=keep; unset _sif; return 0
  fi
  _A_RF=0
  _d4=$IPC
  _d6=""; _v6=0
  if [ -n "$IPT6_BIN" ] && ipt_chain 6 "$C_OUT6"; then _d6=$IPC; _v6=1; fi

  if ! announce_wanted; then
    case "$_d4" in *"$C_OUT"*) _ann_remove 4 "$_d4" "$C_OUT"; log_info "announcement blocking removed" ;; esac
    [ "$_v6" = 1 ] && case "$_d6" in *"$C_OUT6"*) _ann_remove 6 "$_d6" "$C_OUT6" ;; esac
    A_STATE=off
    unset _sif _d4 _d6 _v6
    return 0
  fi

  A_STATE=on
  _ann_expect
  _ann_check "$_d4" "$C_OUT" "$_sif" "$A_E4"
  if [ -n "$A_CHK" ]; then
    A_PROBLEM=$A_CHK
    if ! _ann_apply 4 "$_d4" "$C_OUT" "$_sif" "$A_E4"; then
      A_STATE=error; log_error "could not set the IPv4 announcement rules ($A_CHK)"
    fi
  fi
  if [ "$_v6" = 1 ]; then
    A_V6=1
    _ann_check "$_d6" "$C_OUT6" "$_sif" "$A_E6"
    if [ -n "$A_CHK" ]; then
      A_PROBLEM="${A_PROBLEM:+$A_PROBLEM, }$A_CHK"
      if ! _ann_apply 6 "$_d6" "$C_OUT6" "$_sif" "$A_E6"; then
        A_STATE=error; log_error "could not set the IPv6 announcement rules ($A_CHK)"
      fi
    fi
  fi
  unset _sif _d4 _d6 _v6
  [ "$A_STATE" != error ]
}

announce_teardown() {
  _d4=$(ipt_dump 4 filter) && _ann_remove 4 "$_d4" "$C_OUT"
  [ -n "$IPT6_BIN" ] && _d6=$(ipt_dump 6 filter) && _ann_remove 6 "$_d6" "$C_OUT6"
  unset _d4 _d6
}

# What is blocked, for the log / status
announce_text() { announce_text_get; echo "$A_TEXT"; }
announce_text_get() { # -> A_TEXT (needs conf_load)
  _tx=""
  [ "$S_BLOCK_MDNS" = 1 ] && _tx="mDNS"
  [ "$S_BLOCK_SSDP" = 1 ] && _tx="${_tx:+$_tx, }SSDP"
  [ "$S_BLOCK_LLMNR" = 1 ] && _tx="${_tx:+$_tx, }LLMNR"
  A_TEXT=${_tx:-nothing}
  unset _tx
}
