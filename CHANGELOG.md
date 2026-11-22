# Changelog

## 1.0-r4

* **One phone Back leaves Help** - the contents and the links to other sections no longer add steps to the phone's Back, however many sections you opened
* The module's scripts are unchanged

---

## 1.0-r3

* **The WebUI and Help load nothing from the internet** - the Google web font is gone (it sent a request to Google on every open); the text uses the phone's own monospace font
* **Help reads better on the phone** - table rows are stacked (the name on top, its text under it at full width, no more sideways scrolling), every example command sits in a box with its own **COPY** button (only that one command is copied, never its comment), and an arrow at the bottom right jumps back to the top
* **Help ‹ BACK returns to the dashboard** also after a jump through the contents (it went back only to the top of Help)
* The module's scripts are unchanged

---

## 1.0-r2

* **Uses far less CPU** - the watchdog now does its check every 20 seconds instead of 10 and starts about a tenth of the programs per check. Measured on the phone: from 1.3-2.3 % of one CPU core down to about 0.7 % before the longer interval. The WebUI also answers about three times faster
* **No false "Firewall rules failed" at shutdown** - in the last second before a restart the firewall cannot be read; this is no longer reported as an error in the log, the module description and the status the other modules of the set show
* A settings file edited by hand with Windows line ends (or without a final newline) is read correctly; changing a setting keeps the order of the lines in the file
* The module's files are no longer writable by everyone, and temporary files left by a shutdown are removed at boot

---

## 1.0-r1

* **WebUI opens quickly every time** - after closing and quickly reopening it, the page could wait several seconds before showing anything. The root manager sometimes drops the page's very first command; the page now asks again after a moment instead of waiting for the lost answer
* README: new banner showing the five modules of the networking set

---

## 1.0

First release. Hides the phone from the Wi-Fi network it is connected to.

* **Clean DHCP** - the device name (options 12 and 81) and `android-dhcp-<version>` (option 60) are removed, and Android's parameter request list (option 55) is cut to the 9 entries every client asks for. Each is a switch. Done by an eBPF program in the kernel, in place: same length, correct checksum, never a dropped packet
* **From the first request after boot**, and after every Wi-Fi off / on: a small guard puts the cleaner back each time Android removes it
* **No announcements** - outgoing mDNS, SSDP and LLMNR blocked on Wi-Fi, IPv4 and IPv6, each a switch (casting needs mDNS: switch it off while you cast)
* **Wi-Fi only** - hotspot interfaces, mobile data and VPN tunnels are never touched
* **Off at once** - the master switch or disabling the module in the root manager removes everything without a reboot
* **WebUI** - what the router sees, the DHCP guard's counters, blocked packets, the networking set (WG Shield, DNSCrypt Proxy, VPN Hotspot, ipset), Restart Wi-Fi, log, report, help

Tested on Poco F6 Pro, Xiaomi.eu ROM (HyperOS 3, Android 16), kernel [GKI_Kernel_SukiSU](https://github.com/nikakvo/GKI_Kernel_SukiSU), with a hotspot on at the same time and the whole networking set installed.
