# Third-party notices

The module's own files - scripts, WebUI, the loader `src/lanc-bpf.c` and the
eBPF program `src/dhcp_clean.bpf.c` - are licensed under the
[MIT License](LICENSE), Copyright (c) 2026 Tears Burn (nikakvo). The eBPF
program declares the license string "Dual MIT/GPL", which the Linux kernel
requires for programs that use GPL-only helpers.

The part below is **not** covered by that license and keeps its own terms.

| Part | Origin | License |
|---|---|---|
| musl libc, linked statically into `bin/lanc-bpf` | [musl](https://musl.libc.org/) as shipped with zig 0.16.0 | MIT - Copyright © 2005-2020 Rich Felker, et al. |
