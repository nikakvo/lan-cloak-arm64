// SPDX-License-Identifier: MIT OR GPL-2.0
// LAN Cloak Arm64 - DHCP cleaner (tc clsact egress on the Wi-Fi interface).
//
// Touches only IPv4 UDP 68 -> 67 BOOTREQUEST packets with the DHCP magic
// cookie. Options are changed IN PLACE (the packet length never changes):
//   flag 1: option 12 (host name) and 81 (client FQDN) -> PAD bytes
//   flag 2: option 60 (vendor class)                   -> PAD bytes
//   flag 4: option 55 (parameter request list) keeps only a short common
//           set, in its order; the freed bytes become PAD
// Each change updates the UDP checksum incrementally: bpf_csum_diff of the
// option's bytes before/after, then bpf_l4_csum_replace, which leaves a
// CHECKSUM_PARTIAL packet alone (the NIC sums the final bytes) and keeps a
// zero ("no checksum") UDP field zero.
// Anything unexpected = that change is skipped. Never drops a packet.
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>

#define SEC(x) __attribute__((section(x), used))
#define INL static inline __attribute__((always_inline))

static long (*bpf_skb_load_bytes)(const void *skb, __u32 off, void *to, __u32 len) = (void *)BPF_FUNC_skb_load_bytes;
static long (*bpf_skb_store_bytes)(void *skb, __u32 off, const void *from, __u32 len, __u64 flags) = (void *)BPF_FUNC_skb_store_bytes;
static long (*bpf_l4_csum_replace)(void *skb, __u32 off, __u64 from, __u64 to, __u64 flags) = (void *)BPF_FUNC_l4_csum_replace;
static __s64 (*bpf_csum_diff)(__be32 *from, __u32 from_size, __be32 *to, __u32 to_size, __wsum seed) = (void *)BPF_FUNC_csum_diff;
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static __u64 (*bpf_ktime_get_boot_ns)(void) = (void *)BPF_FUNC_ktime_get_boot_ns;

#define F_HOST   1u
#define F_VENDOR 2u
#define F_PRL    4u

#define MAX_OPT  125   // option data length we change (Android: name <= 63)
#define BUF      128   // region buffer (lead byte + 2 + MAX_OPT <= 128)

// Must match the loader (lanc-bpf.c).
struct lanc_stats {
	__u32 flags;      // written by the loader
	__u32 abi;        // written by the loader
	__u64 seen;       // DHCP client packets seen
	__u64 changed;    // packets changed
	__u64 skipped;    // something could not be changed - sent as it was
	__u64 host;       // option 12/81 removed
	__u64 vendor;     // option 60 removed
	__u64 prl;        // option 55 shortened
	__u64 last_seen;  // CLOCK_BOOTTIME ns
	__u64 last_changed;
};

// The loader turns this 64-bit immediate into the map reference
// (src_reg = BPF_PSEUDO_MAP_FD, imm = map fd). No ELF relocations needed.
INL void *stats_map(void)
{
	void *m;
	asm volatile("%0 = 0x4c414e43 ll" : "=r"(m));
	return m;
}

// Per-CPU scratch: the parse state and the offsets found go through it, so
// the verifier sees them as plain unknown values (otherwise it tracks every
// path through the option loop separately and gives up). tc runs with
// migration disabled, so per-CPU data is private to this packet.
struct lanc_scratch {
	__u32 off[4];   // first 12, 81, 60, 55 (0 = none)
	__u32 cur;      // parse position
	__u32 tmp;      // see launder()
};

INL void *scratch_map(void)
{
	void *m;
	asm volatile("%0 = 0x4c414e44 ll" : "=r"(m));
	return m;
}

// branch-free helpers for small unsigned values (< 2^31)
// Hide a value's known range from clang: otherwise it drops the constant
// loop bounds (i < 64) as redundant and the verifier cannot prove the loop ends.
#define OPAQUE(x) asm volatile("" : "+r"(x))

#define EQ(a, b) (((((a) ^ (b)) - 1) >> 31) & 1)
#define ISZ(x)   ((((x) - 1) >> 31) & 1)

// Codes kept in option 55: subnet 1, router 3, DNS 6, domain 15, MTU 26,
// broadcast 28, lease 51, T1 58, T2 59 - as a bit mask (all codes < 64).
#define PRL_KEEP ((1ull << 1) | (1ull << 3) | (1ull << 6) | (1ull << 15) | \
		  (1ull << 26) | (1ull << 28) | (1ull << 51) | (1ull << 58) | (1ull << 59))

// 1 if code c is kept, else 0 - without branches, so the verifier sees one
// path instead of one per combination of codes.
INL __u32 prl_keep(__u32 c)
{
	__u32 small = ((c + 0xc0) >> 8) ^ 1;          // 1 when c < 64
	return (__u32)((PRL_KEEP >> (c & 63)) & 1) & small;
}

// Pass a size through the scratch map: the verifier then sees an unknown
// value (re-bounded by the mask at the call site) instead of following it
// back through every path that produced it.
INL __u32 launder(struct lanc_scratch *sc, __u32 v)
{
	*(volatile __u32 *)&sc->tmp = v;
	return *(volatile __u32 *)&sc->tmp;
}

struct bufs {
	__u8 old[BUF];
	__u8 new[BUF];
};

INL void bufs_zero(struct bufs *b)
{
	__builtin_memset(b, 0, sizeof(*b));
}

// Region = the option's bytes, starting at the even offset before it (the
// checksum sums 16-bit words starting at the UDP header, which sits at an
// even offset). Load it into old (before) or new (after).
INL int region_load(struct __sk_buff *skb, struct lanc_scratch *sc, __u32 off, __u32 len, __u8 *dst)
{
	__u32 a = off & ~1u;
	__u32 span = (off - a) + len;          // 2 .. 128
	if (span < 2 || span > BUF)
		return -1;
	__u32 sz = (launder(sc, span - 1) & (BUF - 1)) + 1;   // == span
	return bpf_skb_load_bytes(skb, a, dst, sz) < 0 ? -1 : 0;
}

INL int csum_apply(struct __sk_buff *skb, __u32 csum_off, struct bufs *b)
{
	__s64 d = bpf_csum_diff((__be32 *)b->old, BUF, (__be32 *)b->new, BUF, 0);
	if (d < 0)
		return -1;
	return bpf_l4_csum_replace(skb, csum_off, 0, (__u32)d, BPF_F_MARK_MANGLED_0) < 0 ? -1 : 0;
}

// Read the option header at off; it must be code. Returns the data length
// or -1. (The offset came through the scratch map, so check it again.)
INL int opt_len(struct __sk_buff *skb, __u32 off, __u32 code, __u32 end)
{
	__u8 hd[2] = {};
	if (!off || off + 2 > end)
		return -1;
	if (bpf_skb_load_bytes(skb, off, hd, 2) < 0 || hd[0] != code)
		return -1;
	if (off + 2 + hd[1] > end)
		return -1;
	return hd[1];
}

// Replace the whole option at off (code + len + data) with PAD.
INL int pad_option(struct __sk_buff *skb, struct lanc_scratch *sc, __u32 csum_off, __u32 off, __u32 code, __u32 end, struct bufs *b)
{
	int l = opt_len(skb, off, code, end);
	if (l < 0 || l > MAX_OPT)
		return -1;
	__u32 len = (__u32)l + 2;
	bufs_zero(b);
	if (region_load(skb, sc, off, len, b->old) < 0)
		return -1;
	__u32 sz = (launder(sc, len - 1) & (BUF - 1)) + 1;   // == len
	if (bpf_skb_store_bytes(skb, off, b->new, sz, 0) < 0)   // new is all zero here
		return -1;
	if (region_load(skb, sc, off, len, b->new) < 0)
		return -1;
	return csum_apply(skb, csum_off, b);
}

// Option 55: keep only the common codes, in their order (compacted in
// place); the freed bytes become PAD. 0 = changed, 1 = nothing to do.
INL int trim_prl(struct __sk_buff *skb, struct lanc_scratch *sc, __u32 csum_off, __u32 off, __u32 end, struct bufs *b)
{
	__u32 keep = 0, m = 0;
	__u8 c = 0, z = 0;
	int l = opt_len(skb, off, 55, end);
	if (l < 0)
		return -1;
	__u32 plen = (__u32)l;
	if (plen < 1 || plen > 64)
		return 1;
	OPAQUE(plen);
	for (int i = 0; i < 64; i++) {          // count first
		if (i >= plen)
			break;
		if (bpf_skb_load_bytes(skb, off + 2 + i, &c, 1) < 0)
			return -1;
		keep += prl_keep(c);
	}
	if (keep >= plen || keep == 0)
		return 1;   // nothing to drop / would empty the list: leave it
	OPAQUE(plen);
	bufs_zero(b);
	if (region_load(skb, sc, off, plen + 2, b->old) < 0)
		return -1;
	// Compact: every byte is written at m (m <= i, so writes never pass the
	// reads); a dropped code is overwritten by the next kept one or by PAD.
	for (int i = 0; i < 64; i++) {
		if (i >= plen)
			break;
		if (bpf_skb_load_bytes(skb, off + 2 + i, &c, 1) < 0)
			return -1;
		if (bpf_skb_store_bytes(skb, off + 2 + m, &c, 1, 0) < 0)
			return -1;
		m += prl_keep(c);
	}
	for (int i = 0; i < 64; i++) {          // PAD the freed tail
		if (m + i >= plen)
			break;
		if (bpf_skb_store_bytes(skb, off + 2 + m + i, &z, 1, 0) < 0)
			return -1;
	}
	c = (__u8)m;
	if (bpf_skb_store_bytes(skb, off + 1, &c, 1, 0) < 0)
		return -1;
	if (region_load(skb, sc, off, plen + 2, b->new) < 0)
		return -1;
	return csum_apply(skb, csum_off, b);
}

SEC("tc")
int lanc_dhcp(struct __sk_buff *skb)
{
	if (skb->protocol != __builtin_bswap16(ETH_P_IP))
		return TC_ACT_UNSPEC;

	__u8 ip[20];
	if (bpf_skb_load_bytes(skb, ETH_HLEN, ip, 20) < 0)
		return TC_ACT_UNSPEC;
	if ((ip[0] >> 4) != 4 || ip[9] != 17)
		return TC_ACT_UNSPEC;
	if (((ip[6] & 0x3f) | ip[7]) != 0)       // MF or fragment offset
		return TC_ACT_UNSPEC;
	__u32 ihl = (ip[0] & 0x0f) * 4;
	if (ihl < 20)
		return TC_ACT_UNSPEC;
	__u32 u = ETH_HLEN + ihl;

	__u8 udp[8];
	if (bpf_skb_load_bytes(skb, u, udp, 8) < 0)
		return TC_ACT_UNSPEC;
	if (udp[0] != 0 || udp[1] != 68 || udp[2] != 0 || udp[3] != 67)
		return TC_ACT_UNSPEC;

	__u32 key = 0;
	struct lanc_stats *st = bpf_map_lookup_elem(stats_map(), &key);
	if (!st)
		return TC_ACT_UNSPEC;

	__u32 d = u + 8;
	__u8 op = 0;
	__u32 cookie = 0;
	if (bpf_skb_load_bytes(skb, d, &op, 1) < 0 || op != 1)
		return TC_ACT_UNSPEC;
	if (bpf_skb_load_bytes(skb, d + 236, &cookie, 4) < 0 ||
	    cookie != __builtin_bswap32(0x63825363))
		return TC_ACT_UNSPEC;

	__u64 now = bpf_ktime_get_boot_ns();
	__sync_fetch_and_add(&st->seen, 1);
	st->last_seen = now;
	__u32 flags = st->flags;
	if (!(flags & (F_HOST | F_VENDOR | F_PRL)))
		return TC_ACT_UNSPEC;

	__u32 ulen = ((__u32)udp[4] << 8) | udp[5];
	__u32 end = u + ulen;
	if (ulen < 8 + 240 || end > skb->len) {
		__sync_fetch_and_add(&st->skipped, 1);
		return TC_ACT_UNSPEC;
	}
	__u32 csum_off = u + 6;

	struct lanc_scratch *sc = bpf_map_lookup_elem(scratch_map(), &key);
	if (!sc)
		return TC_ACT_UNSPEC;

	// Pass 1: find the options (first occurrence of each). Everything that
	// lives from one iteration to the next is kept in the per-CPU scratch
	// (volatile), so for the verifier each iteration starts from the same
	// "unknown values" state: it checks the loop once per iteration instead
	// of once per possible combination of options.
	volatile __u32 *vo = sc->off;
	volatile __u32 *vcur = &sc->cur;
	vo[0] = 0; vo[1] = 0; vo[2] = 0; vo[3] = 0;
	*vcur = d + 240;
	int ok = 0;
	for (int i = 0; i < 64; i++) {
		__u32 off = *vcur;
		if (off >= end)
			break;
		__u8 hd[2] = {};
		if (bpf_skb_load_bytes(skb, off, hd, 2) < 0) {
			// only the END byte can be the very last byte
			if (bpf_skb_load_bytes(skb, off, hd, 1) < 0 || hd[0] != 255)
				break;
		}
		if (hd[0] == 255) {
			ok = 1;
			break;
		}
		if (hd[0] == 0) {
			*vcur = off + 1;
			continue;
		}
		__u32 code = hd[0], l = hd[1];
		if (off + 2 + l > end)
			break;
		// remember the first 12/81/60/55 - branch free (see prl_keep)
		vo[0] += (EQ(code, 12) & ISZ(vo[0])) * off;
		vo[1] += (EQ(code, 81) & ISZ(vo[1])) * off;
		vo[2] += (EQ(code, 60) & ISZ(vo[2])) * off;
		vo[3] += (EQ(code, 55) & ISZ(vo[3])) * off;
		*vcur = off + 2 + l;
	}
	if (!ok) {
		__sync_fetch_and_add(&st->skipped, 1);
		return TC_ACT_UNSPEC;
	}

	// Pass 2: change them. Each change is complete on its own (bytes + checksum).
	struct bufs b;
	int changed = 0, bad = 0;
	if (flags & F_HOST) {
		__u32 o1 = sc->off[0], o2 = sc->off[1];
		int r1 = o1 ? pad_option(skb, sc, csum_off, o1, 12, end, &b) : 1;
		int r2 = o2 ? pad_option(skb, sc, csum_off, o2, 81, end, &b) : 1;
		if (r1 < 0 || r2 < 0)
			bad = 1;
		if (r1 == 0 || r2 == 0) {
			changed = 1;
			__sync_fetch_and_add(&st->host, 1);
		}
	}
	if (flags & F_VENDOR) {
		__u32 o = sc->off[2];
		if (o) {
			if (pad_option(skb, sc, csum_off, o, 60, end, &b) < 0)
				bad = 1;
			else {
				changed = 1;
				__sync_fetch_and_add(&st->vendor, 1);
			}
		}
	}
	if (flags & F_PRL) {
		__u32 o = sc->off[3];
		if (o) {
			int r = trim_prl(skb, sc, csum_off, o, end, &b);
			if (r < 0)
				bad = 1;
			else if (r == 0) {
				changed = 1;
				__sync_fetch_and_add(&st->prl, 1);
			}
		}
	}
	if (bad)
		__sync_fetch_and_add(&st->skipped, 1);
	if (changed) {
		__sync_fetch_and_add(&st->changed, 1);
		st->last_changed = now;
	}
	return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "Dual MIT/GPL";
