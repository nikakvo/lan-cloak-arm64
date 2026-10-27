<p align="center"><img src="lan-cloak.png" alt="LAN Cloak Arm64"></p>

<p align="center">
  <img src="https://img.shields.io/badge/ARM64-only-ff3dd2?style=flat-square" />
  <img src="https://img.shields.io/badge/v1.0-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/SukiSU%20%2F%20KernelSU%20%2F%20Magisk-compatible-brightgreen?style=flat-square" />
  <img src="https://img.shields.io/badge/DHCP%20cleaner-eBPF-ff3dd2?style=flat-square" />
  <img src="https://img.shields.io/badge/WebUI-built%20in-ff3dd2?style=flat-square" />
</p>

# LAN Cloak - arm64

**Hides the phone from the Wi-Fi network it is connected to.** A VPN hides what the phone does on the internet, but not what it tells the local network: every Android phone sends its **device name** and **"android-dhcp-16"** to the router when it connects, asks for a list of settings that identifies it as Android, and keeps **announcing itself and its apps** to every device around (mDNS, SSDP, LLMNR). LAN Cloak removes all of that - the DHCP request is cleaned in the kernel on its way out, the announcements are dropped before they leave the phone. Every part is a switch.

No LSPosed, no app, no changes to Android: an eBPF program on the Wi-Fi interface and a few firewall rules, both removed at once when you switch the module off.

<img width="300" alt="LAN Cloak WebUI" src="https://raw.githubusercontent.com/nikakvo/lan-cloak-arm64/main/lan-cloak-arm64.jpg" />

---

## What the router sees

| | Without | With LAN Cloak |
|---|---|---|
| Device name (DHCP 12, 81) | `POCO-F6-Pro` | nothing |
| Vendor class (DHCP 60) | `android-dhcp-16` | nothing |
| Parameter request list (DHCP 55) | `1,3,6,15,26,28,51,58,59,43,114,108` - Android's fingerprint | `1,3,6,15,26,28,51,58,59` - what every client asks for |
| mDNS | the phone and its apps (`_googlecast`, `_tidalconnect`, `_sonycast`, Xiaomi HyperConnect…) every few seconds | nothing |
| SSDP | UPnP searches | nothing |
| LLMNR | name lookups to every device | nothing |

---

## Features

- **Clean DHCP** - device name, vendor class and Android's request list removed, each with its own switch. Done in place in the kernel: the packet keeps its length, the checksum is corrected, nothing is ever dropped
- **First request after boot is clean too** - the DHCP guard starts at early boot, before Wi-Fi
- **Survives every Wi-Fi off / on** - Android deletes the interface's traffic-control setup each time; the guard puts the cleaner back within about half a second, seconds before Android's next request
- **Silent on the LAN** - outgoing mDNS, SSDP and LLMNR blocked on Wi-Fi (IPv4 and IPv6), each a switch: turn mDNS off while you cast to a TV
- **Wi-Fi only** - hotspot interfaces, mobile data and VPN tunnels are never touched
- **Off means off** - switch it off in the WebUI or disable it in the root manager: everything is removed at once, no reboot
- **WebUI** - *Seen by the router* at a glance, the DHCP guard's counters, blocked packets per protocol, the networking set, Restart Wi-Fi, log, report, help

---

## How it works

```
Android's DHCP client                         apps / Android announcing themselves
        ↓                                                     ↓
tc egress on wlan0: lan_cloak_dhcp (eBPF)      iptables OUTPUT -o wlan0 → LANC_OUT / LANC_OUT6
  options 12, 81, 60 → padding                   mDNS 5353, SSDP 1900, LLMNR 5355 → DROP
  option 55 → the 9 common entries
        ↓
      router
```

**DHCP cleaner.** A small tc classifier (`bin/lanc-bpf`, static arm64, loader and program in one file) on the Wi-Fi interface's egress, priority 10. It looks only at DHCP requests from the phone (UDP 68 → 67) and overwrites the chosen options with padding in place - same length, checksum fixed incrementally, `TC_ACT_UNSPEC` always (it never drops). Android's own `clsact` and filters are never replaced or deleted.

**DHCP guard.** `lanc-bpf watch` follows the interface over netlink. When Android removes `clsact` at Wi-Fi off, the guard waits half a second for its owner, then creates it and attaches the cleaner again (about 20 ms). Measured on the phone: the cleaner is back a few seconds before Android's next DHCP request. A side effect: netd logs `tcQdiscAddDevClsact(...[wlan0]) failure: File exists` at every Wi-Fi on - harmless, netd adds no filters there.

**Announcements.** One jump per family at the end of `OUTPUT`, only for the Wi-Fi interface; the chains only drop, never accept, so nothing of Android's or the sibling modules' rules is skipped.

**Watchdog.** Every 10 s (2 s in the first 2 minutes after boot): the guard runs with the right settings on the right interface, the rules are complete. Anything off is put back and logged.

---

## Requirements

| | |
|---|---|
| CPU | arm64 |
| Kernel | eBPF + tc classifiers (`CONFIG_BPF_SYSCALL`, `CONFIG_NET_CLS_BPF`, `CONFIG_NET_SCH_INGRESS`) - every Android GKI kernel has them. The installer loads the cleaner once to check; without it, only the announcement blocking works |
| Root | SukiSU Ultra or KernelSU (WebUI built in) · APatch · Magisk (WebUI via MMRL or KSU WebUI Standalone) |
| Android | 12+ (tested on 16) |

### Tested on

Poco F6 Pro (vermeer), Xiaomi.eu ROM (HyperOS 3, Android 16), custom kernel [GKI_Kernel_SukiSU](https://github.com/nikakvo/GKI_Kernel_SukiSU) (5.15, SukiSU Ultra) - on Wi-Fi with a hotspot at the same time, together with DNSCrypt Proxy Arm64, ipset-arm64, VPN Hotspot Arm64 and WG Shield Arm64. The DHCP client is Android's own NetworkStack, the same on every ROM, but other devices are not tested - reports welcome.

---

## Installation

1. Flash `lan-cloak-arm64-vX.X.zip` in your root manager, reboot. Everything is on
2. Open the WebUI - *Seen by the router* shows four magenta tiles
3. Tap **Restart Wi-Fi** (twice) so a clean DHCP request goes out now
4. You cast to a TV / Chromecast or print over Wi-Fi? Settings → turn **Block mDNS** (and **Block SSDP** for DLNA) off

The router may keep showing the old name until its lease ends (often 12-24 h), or until you remove the phone from its device list. Settings are kept on update.

---

## WebUI

| Tab | |
|---|---|
| Top | *Seen by the router*: device name, vendor, fingerprint, announcements - magenta hidden, orange sent, red failed · MAC and IP · Restart Wi-Fi |
| Dashboard | DHCP guard (last request, seen / cleaned, what was removed) · blocked packets per protocol · the networking set · watchdog |
| Settings | Master switch · the three DHCP switches · mDNS / SSDP / LLMNR · Wi-Fi interface (auto / custom) · Check now · Report |
| Log | Module log and the DHCP guard's own log, filterable, clearable |

---

## What it does not hide

- **The MAC address** - Android's own: a random address per network by default (the WebUI says so). The same network sees the same random address each time
- **That the phone is there** - its address, when and how much it sends
- **Android's network check** and everything else on the internet side - that is the VPN's job ([WG Shield Arm64](https://github.com/nikakvo/wg-shield-arm64))
- **Other networks** - hotspot devices, mobile data, USB / Ethernet adapters

Casting to a TV, Spotify Connect lists, printer discovery and "devices nearby" need mDNS (DLNA needs SSDP): they stop while those two are blocked.

---

## The networking set

Five modules built to work together - each one works on its own:

| | Module | What it adds |
|---|---|---|
| 🟢 | [DNSCrypt Proxy Arm64](https://github.com/nikakvo/dnscrypt-proxy-android-arm64-only) | Encrypted DNS with ad / tracker blocklists - name lookups never reach the router in clear |
| 🔵 | [ipset-arm64](https://github.com/nikakvo/ipset_arm64) | IP blocklists (FireHOL, Spamhaus) in the kernel |
| 🟡 | [VPN Hotspot Arm64](https://github.com/nikakvo/vpn-hotspot-arm64) | Sends hotspot, USB and Bluetooth devices through the phone's VPN, with kill switch |
| 🩵 | [WG Shield Arm64](https://github.com/nikakvo/wg-shield-arm64) | Always-on kernel WireGuard / AmneziaWG, with kill switch - no app |
| 🩷 | **LAN Cloak Arm64** *(this module)* | What the local network sees of the phone: clean DHCP, no announcements |

```
what the local network sees of the phone → LAN Cloak
name lookups                             → DNSCrypt Proxy
where internet traffic goes              → WG Shield (ipset blocks listed networks)
hotspot devices                          → VPN Hotspot
```

No overlaps: LAN Cloak uses a tc filter and two firewall chains of its own on the Wi-Fi interface; WG Shield routing only; VPN Hotspot the hotspot interfaces. The WebUI shows the other four and their state.

---

## Files

| Path | |
|---|---|
| `/data/adb/lan-cloak/` | Everything the module keeps, in one folder: |
| `  settings.conf` | Settings (kept on update) |
| `  logs/lan-cloak.log` | Module log |
| `  logs/dhcp-guard.log` | DHCP guard log (Wi-Fi events, re-attach times) |
| `  state/` | Runtime state, cleared at boot; `status` can be read by other modules |
| `bin/lanc-bpf` | The DHCP cleaner and its guard, static arm64 (source in `src/`) |

### Status file (for other modules)

`/data/adb/lan-cloak/state/status`, rewritten atomically on every watchdog pass:

```
state=on|off|error          reason=disabled|module-disabled|nothing-selected|dhcp|firewall
iface=wlan0                 wifi=connected|disconnected|absent
dhcp=on|waiting|off|error   dhcp_flags=0-7 (1 name, 2 vendor, 4 list)   dhcp_guard=running|stopped
dhcp_seen=… dhcp_changed=… dhcp_skipped=…   dhcp_last_seen_at=<epoch>
announce=on|off|error       announce_ipv6=1|0   block_mdns / block_ssdp / block_llmnr=1|0
blocked_mdns / blocked_ssdp / blocked_llmnr=<packets>        updated=<epoch>
```

---

## Command line

```sh
# from Termux
su -c '/system/bin/sh /data/adb/modules/lan-cloak/ctl.sh status'
su -c '/system/bin/sh /data/adb/modules/lan-cloak/ctl.sh set BLOCK_MDNS 0'   # mDNS allowed (casting)
su -c '/system/bin/sh /data/adb/modules/lan-cloak/ctl.sh set BLOCK_MDNS 1'
su -c '/system/bin/sh /data/adb/modules/lan-cloak/ctl.sh set ENABLED 0'      # everything off
su -c '/system/bin/sh /data/adb/modules/lan-cloak/ctl.sh dhcp'               # the cleaner's counters
su -c '/system/bin/sh /data/adb/modules/lan-cloak/ctl.sh wifi-restart'       # a new DHCP request now
su -c '/system/bin/sh /data/adb/modules/lan-cloak/ctl.sh log 100'
su -c '/system/bin/sh /data/adb/modules/lan-cloak/ctl.sh guardlog 100'
su -c '/system/bin/sh /data/adb/modules/lan-cloak/ctl.sh diag'               # report
su -c '/system/bin/sh /data/adb/modules/lan-cloak/ctl.sh help'               # every command and setting
```

Settings: `ENABLED`, `DHCP_HOSTNAME`, `DHCP_VENDOR`, `DHCP_PRL`, `BLOCK_MDNS`, `BLOCK_SSDP`, `BLOCK_LLMNR` (`0` / `1`), `WIFI_IFACE` (`auto` or an interface name).

---

## Verify

Capture on the phone (from a Linux chroot such as Kali), then Restart Wi-Fi:

```
tcpdump -i wlan0 -n -vvv 'udp port 67 or udp port 68'
```

The request has no *Hostname*, no *Vendor-Class*, and a *Parameter-Request* with 9 entries; `udp sum ok`, the router answers with an ACK. For the announcements: `tcpdump -i wlan0 -n 'udp port 5353 or udp port 1900 or udp port 5355'` shows nothing from the phone's address.

---

## Uninstall

Remove the module in your root manager and reboot. The cleaner, the guard and every rule are removed, then the data folder is deleted.

---

## Build `lanc-bpf`

`build.sh` (in this repo) compiles the eBPF program (`src/dhcp_clean.bpf.c`) with clang, embeds it into the loader (`src/lanc-bpf.c`) and builds a static arm64 binary with [zig](https://ziglang.org):

```sh
sh build.sh                    # → bin/lanc-bpf
ZIG=/path/to/zig sh build.sh
```

Needs clang with the BPF target, llvm-objcopy, llvm-readelf and zig 0.16.0. The build is reproducible; SHA-256 of `bin/lanc-bpf` in the release: `61e66e79e49cc680832654bd97f8a6100d4d6e188009f81c3f79bb5b0242cdb0`.

---

## License

[MIT](LICENSE). The eBPF program is licensed "Dual MIT/GPL" (the kernel requires a GPL-compatible license string for it). `bin/lanc-bpf` is linked statically with musl libc (MIT) - see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
