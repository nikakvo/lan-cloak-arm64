# Changelog

## 1.0

First release. Hides the phone from the Wi-Fi network it is connected to.

* **Clean DHCP** - the device name (options 12 and 81) and `android-dhcp-<version>` (option 60) are removed, and Android's parameter request list (option 55) is cut to the 9 entries every client asks for. Each is a switch. Done by an eBPF program in the kernel, in place: same length, correct checksum, never a dropped packet
* **From the first request after boot**, and after every Wi-Fi off / on: a small guard puts the cleaner back each time Android removes it
* **No announcements** - outgoing mDNS, SSDP and LLMNR blocked on Wi-Fi, IPv4 and IPv6, each a switch (casting needs mDNS: switch it off while you cast)
* **Wi-Fi only** - hotspot interfaces, mobile data and VPN tunnels are never touched
* **Off at once** - the master switch or disabling the module in the root manager removes everything without a reboot
* **WebUI** - what the router sees, the DHCP guard's counters, blocked packets, the networking set (WG Shield, DNSCrypt Proxy, VPN Hotspot, ipset), Restart Wi-Fi, log, report, help

Tested on Poco F6 Pro, Xiaomi.eu ROM (HyperOS 3, Android 16), kernel [GKI_Kernel_SukiSU](https://github.com/nikakvo/GKI_Kernel_SukiSU), with a hotspot on at the same time and the whole networking set installed.
