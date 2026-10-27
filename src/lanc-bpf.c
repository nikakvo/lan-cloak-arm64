// SPDX-License-Identifier: MIT
// lanc-bpf - LAN Cloak Arm64 eBPF helper (load / attach / detach / status).
//
//   lanc-bpf attach <iface> <flags>   load the DHCP cleaner, attach it to
//                                     <iface> clsact egress (adds clsact only
//                                     if missing, never replaces it); an
//                                     existing LAN Cloak filter is replaced
//                                     in place (no gap)
//   lanc-bpf set <iface> <flags>      change the flags of the attached program
//   lanc-bpf detach <iface>           remove LAN Cloak's filter only
//   lanc-bpf status <iface>           key=value report + counters
//   lanc-bpf monitor <iface> [log]   only log tc / link events (who changes
//                                     the interface's qdiscs and filters)
//   lanc-bpf watch <iface> <flags> [log]
//                                     attach, then stay running: listen to tc
//                                     netlink events and re-attach at once when
//                                     Android re-creates the interface's clsact
//                                     (that removes every filter on it); with a
//                                     log file it detaches from the terminal
//                                     (daemon, pid in <log>.pid or $LANC_PIDFILE).
//                                     SIGTERM = stop and remove the filter.
//
// flags: 1 = remove host name (12, 81), 2 = remove vendor class (60),
//        4 = shorten parameter request list (55)
// The program bytes are embedded (dhcp_clean.h, built from dhcp_clean.bpf.c).
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <net/if.h>
#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP 0x10000
#endif
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <arpa/inet.h>

#include "dhcp_clean.h"

#define LANC_PRIO   10        // tc filter preference (Android uses 1-3)
#define LANC_HANDLE 1
#define LANC_NAME   "lan_cloak_dhcp"
#define LANC_ABI    1
#define MAP_MAGIC   0x4c414e43   // stats map
#define SCR_MAGIC   0x4c414e44   // per-CPU scratch map

struct lanc_stats {
	uint32_t flags, abi;
	uint64_t seen, changed, skipped, host, vendor, prl, last_seen, last_changed;
};

static long sys_bpf(int cmd, union bpf_attr *a)
{
	return syscall(__NR_bpf, cmd, a, sizeof(*a));
}

static void die(const char *what, int err)
{
	printf("ok=0\nerror=%s\nerrno=%d\nerrstr=%s\n", what, err, strerror(err));
	exit(1);
}

/* ---------------- netlink ---------------- */

struct req {
	struct nlmsghdr n;
	struct tcmsg t;
	char buf[512];
};

static struct rtattr *addattr(struct nlmsghdr *n, int type, const void *data, int len)
{
	struct rtattr *rta = (struct rtattr *)((char *)n + NLMSG_ALIGN(n->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = RTA_LENGTH(len);
	if (len)
		memcpy(RTA_DATA(rta), data, len);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(rta->rta_len);
	return rta;
}

static void nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
	nest->rta_len = (char *)n + NLMSG_ALIGN(n->nlmsg_len) - (char *)nest;
}

static int nl_open(void)
{
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0)
		die("netlink_socket", errno);
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		die("netlink_bind", errno);
	return fd;
}

// Send one request, wait for its ACK. Returns 0 or -errno.
static int nl_talk(int fd, struct nlmsghdr *n)
{
	static uint32_t seq = 100;
	n->nlmsg_seq = ++seq;
	n->nlmsg_flags |= NLM_F_ACK;
	if (send(fd, n, n->nlmsg_len, 0) < 0)
		return -errno;
	char buf[8192];
	for (;;) {
		int len = recv(fd, buf, sizeof(buf), 0);
		if (len < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (unsigned)len); h = NLMSG_NEXT(h, len)) {
			if (h->nlmsg_seq != n->nlmsg_seq)
				continue;
			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *e = NLMSG_DATA(h);
				return e->error;
			}
		}
	}
}

static void req_init(struct req *r, int type, int flags, int ifindex, uint32_t parent)
{
	memset(r, 0, sizeof(*r));
	r->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	r->n.nlmsg_type = type;
	r->n.nlmsg_flags = NLM_F_REQUEST | flags;
	r->t.tcm_family = AF_UNSPEC;
	r->t.tcm_ifindex = ifindex;
	r->t.tcm_parent = parent;
}

#define EGRESS_PARENT TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS)
#define FILTER_INFO   TC_H_MAKE((uint32_t)LANC_PRIO << 16, htons(ETH_P_IP))

static int ensure_clsact(int fd, int ifindex)
{
	struct req r;
	req_init(&r, RTM_NEWQDISC, NLM_F_CREATE | NLM_F_EXCL, ifindex, TC_H_CLSACT);
	r.t.tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0);
	addattr(&r.n, TCA_KIND, "clsact", 7);
	int e = nl_talk(fd, &r.n);
	if (e == -EEXIST)
		return 0;   // Android's own clsact (or ours from before) - keep it
	return e;
}

static int filter_attach(int fd, int ifindex, int prog_fd)
{
	struct req r;
	// NLM_F_CREATE without EXCL = create or replace in place
	req_init(&r, RTM_NEWTFILTER, NLM_F_CREATE, ifindex, EGRESS_PARENT);
	r.t.tcm_handle = LANC_HANDLE;
	r.t.tcm_info = FILTER_INFO;
	addattr(&r.n, TCA_KIND, "bpf", 4);
	struct rtattr *opt = addattr(&r.n, TCA_OPTIONS | NLA_F_NESTED, NULL, 0);
	uint32_t pfd = prog_fd, fl = TCA_BPF_FLAG_ACT_DIRECT;
	addattr(&r.n, TCA_BPF_FD, &pfd, 4);
	addattr(&r.n, TCA_BPF_NAME, LANC_NAME, sizeof(LANC_NAME));
	addattr(&r.n, TCA_BPF_FLAGS, &fl, 4);
	nest_end(&r.n, opt);
	return nl_talk(fd, &r.n);
}

static int filter_detach(int fd, int ifindex)
{
	struct req r;
	req_init(&r, RTM_DELTFILTER, 0, ifindex, EGRESS_PARENT);
	r.t.tcm_info = FILTER_INFO;   // handle 0 = every filter at our prio
	int e = nl_talk(fd, &r.n);
	if (e == -ENOENT || e == -EINVAL)
		return 1;   // nothing there (EINVAL: no clsact at all)
	return e;
}

// Find our filter on egress. Returns the program id, 0 if not attached.
static uint32_t filter_find(int fd, int ifindex, char *name, size_t nsz)
{
	struct req r;
	req_init(&r, RTM_GETTFILTER, NLM_F_DUMP, ifindex, EGRESS_PARENT);
	static uint32_t seq = 900;
	r.n.nlmsg_seq = ++seq;
	if (send(fd, &r, r.n.nlmsg_len, 0) < 0)
		return 0;
	uint32_t id = 0;
	char buf[16384];
	for (;;) {
		int len = recv(fd, buf, sizeof(buf), 0);
		if (len <= 0)
			return id;
		for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (unsigned)len); h = NLMSG_NEXT(h, len)) {
			if (h->nlmsg_type == NLMSG_DONE || h->nlmsg_type == NLMSG_ERROR)
				return id;
			if (h->nlmsg_type != RTM_NEWTFILTER)
				continue;
			struct tcmsg *t = NLMSG_DATA(h);
			if ((t->tcm_info >> 16) != LANC_PRIO || t->tcm_handle != LANC_HANDLE)
				continue;
			int alen = h->nlmsg_len - NLMSG_LENGTH(sizeof(*t));
			int is_bpf = 0;
			struct rtattr *opts = NULL;
			for (struct rtattr *a = TCA_RTA(t); RTA_OK(a, alen); a = RTA_NEXT(a, alen)) {
				if (a->rta_type == TCA_KIND && !strcmp(RTA_DATA(a), "bpf"))
					is_bpf = 1;
				if ((a->rta_type & ~NLA_F_NESTED) == TCA_OPTIONS)
					opts = a;
			}
			if (!is_bpf || !opts)
				continue;
			int olen = RTA_PAYLOAD(opts);
			for (struct rtattr *a = RTA_DATA(opts); RTA_OK(a, olen); a = RTA_NEXT(a, olen)) {
				if (a->rta_type == TCA_BPF_ID)
					id = *(uint32_t *)RTA_DATA(a);
				if (a->rta_type == TCA_BPF_NAME && name)
					snprintf(name, nsz, "%s", (char *)RTA_DATA(a));
			}
		}
	}
}

/* ---------------- bpf ---------------- */

static int map_create(int type, int vsize, const char *name)
{
	union bpf_attr a;
	memset(&a, 0, sizeof(a));
	a.map_type = type;
	a.key_size = 4;
	a.value_size = vsize;
	a.max_entries = 1;
	snprintf(a.map_name, sizeof(a.map_name), "%s", name);
	int fd = sys_bpf(BPF_MAP_CREATE, &a);
	if (fd < 0) {   // very old kernels reject map_name
		memset(a.map_name, 0, sizeof(a.map_name));
		fd = sys_bpf(BPF_MAP_CREATE, &a);
	}
	return fd;
}

static int map_rw(int fd, struct lanc_stats *v, int write)
{
	union bpf_attr a;
	uint32_t key = 0;
	memset(&a, 0, sizeof(a));
	a.map_fd = fd;
	a.key = (uint64_t)(uintptr_t)&key;
	a.value = (uint64_t)(uintptr_t)v;
	return sys_bpf(write ? BPF_MAP_UPDATE_ELEM : BPF_MAP_LOOKUP_ELEM, &a);
}

static char vlog[4 << 20];

static int prog_load(int map_fd, int scr_fd)
{
	size_t n = sizeof(dhcp_clean_insns) / sizeof(struct bpf_insn);
	struct bpf_insn *ins = malloc(sizeof(dhcp_clean_insns));
	if (!ins)
		die("oom", ENOMEM);
	memcpy(ins, dhcp_clean_insns, sizeof(dhcp_clean_insns));
	int p1 = 0, p2 = 0;
	for (size_t i = 0; i + 1 < n; i++) {
		if (ins[i].code != (BPF_LD | BPF_DW | BPF_IMM) || ins[i + 1].imm != 0)
			continue;
		if ((uint32_t)ins[i].imm == MAP_MAGIC) {
			ins[i].src_reg = BPF_PSEUDO_MAP_FD;
			ins[i].imm = map_fd;
			p1++;
			i++;
		} else if ((uint32_t)ins[i].imm == SCR_MAGIC) {
			ins[i].src_reg = BPF_PSEUDO_MAP_FD;
			ins[i].imm = scr_fd;
			p2++;
			i++;
		}
	}
	if (!p1 || !p2)
		die("map_reference_not_found", EINVAL);
	union bpf_attr a;
	memset(&a, 0, sizeof(a));
	a.prog_type = BPF_PROG_TYPE_SCHED_CLS;
	a.insns = (uint64_t)(uintptr_t)ins;
	a.insn_cnt = n;
	a.license = (uint64_t)(uintptr_t)"Dual MIT/GPL";
	snprintf(a.prog_name, sizeof(a.prog_name), "lanc_dhcp");
	if (getenv("LANC_VLOG")) {
		a.log_buf = (uint64_t)(uintptr_t)vlog;
		a.log_size = sizeof(vlog);
		a.log_level = 4;   // statistics only
	}
	int fd = sys_bpf(BPF_PROG_LOAD, &a);
	int first = errno;
	if (fd >= 0 && getenv("LANC_VLOG"))
		fprintf(stderr, "%s", vlog);
	if (fd < 0 && errno != EPERM) {   // retry with the verifier log for the report
		a.log_buf = (uint64_t)(uintptr_t)vlog;
		a.log_size = sizeof(vlog);
		a.log_level = 1;
		fd = sys_bpf(BPF_PROG_LOAD, &a);
		if (fd < 0) {
			int e = errno;
			size_t l = strlen(vlog);
			const char *tail = l > 1500 ? vlog + l - 1500 : vlog;
			fprintf(stderr, "%s\n", tail);
			errno = e == ENOSPC ? first : e;
		}
	}
	free(ins);
	return fd;
}

// map fd of the program attached with id
static int map_of_prog(uint32_t prog_id)
{
	union bpf_attr a;
	memset(&a, 0, sizeof(a));
	a.prog_id = prog_id;
	int pfd = sys_bpf(BPF_PROG_GET_FD_BY_ID, &a);
	if (pfd < 0)
		return -1;
	uint32_t ids[4] = {0};
	struct bpf_prog_info info;
	memset(&info, 0, sizeof(info));
	info.nr_map_ids = 4;
	info.map_ids = (uint64_t)(uintptr_t)ids;
	memset(&a, 0, sizeof(a));
	a.info.bpf_fd = pfd;
	a.info.info_len = sizeof(info);
	a.info.info = (uint64_t)(uintptr_t)&info;
	int rc = sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &a);
	close(pfd);
	if (rc < 0 || info.nr_map_ids < 1)
		return -1;
	for (uint32_t k = 0; k < info.nr_map_ids && k < 4; k++) {
		memset(&a, 0, sizeof(a));
		a.map_id = ids[k];
		int mfd = sys_bpf(BPF_MAP_GET_FD_BY_ID, &a);
		if (mfd < 0)
			continue;
		struct bpf_map_info mi;
		memset(&mi, 0, sizeof(mi));
		memset(&a, 0, sizeof(a));
		a.info.bpf_fd = mfd;
		a.info.info_len = sizeof(mi);
		a.info.info = (uint64_t)(uintptr_t)&mi;
		if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &a) == 0 && mi.type == BPF_MAP_TYPE_ARRAY &&
		    mi.value_size == sizeof(struct lanc_stats))
			return mfd;
		close(mfd);
	}
	return -1;
}

static uint64_t boot_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_BOOTTIME, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static void age(const char *key, uint64_t ns, uint64_t now)
{
	if (!ns || ns > now)
		printf("%s=\n", key);
	else
		printf("%s=%llu\n", key, (unsigned long long)((now - ns) / 1000000000ull));
}

static unsigned parse_flags(const char *s)
{
	char *e;
	unsigned long v = strtoul(s, &e, 10);
	if (*e || v > 7)
		die("bad_flags", EINVAL);
	return (unsigned)v;
}

/* ---------------- watch ---------------- */

static volatile sig_atomic_t stop_flag;
static void on_term(int sig) { (void)sig; stop_flag = 1; }

// Local time: musl cannot read Android's time zone data, so the scripts
// pass the offset (date +%z, e.g. +0200). LANC_TZ_FILE = a file holding it,
// read again every 60 s (the daemon starts at early boot, before Android
// knows the time zone, and runs across DST changes); LANC_TZ = fixed offset.
static long parse_tz(const char *z)
{
	if (z && (z[0] == '+' || z[0] == '-') && strlen(z) >= 5 &&
	    z[1] >= '0' && z[1] <= '9' && z[2] >= '0' && z[2] <= '9' &&
	    z[3] >= '0' && z[3] <= '9' && z[4] >= '0' && z[4] <= '9') {
		long h = (z[1] - '0') * 10 + (z[2] - '0'), m = (z[3] - '0') * 10 + (z[4] - '0');
		return (h * 3600 + m * 60) * (z[0] == '-' ? -1 : 1);
	}
	return 0;
}

static long tz_off(void)
{
	static long off;
	static int have;
	static time_t last;
	const char *zf = getenv("LANC_TZ_FILE");
	if (zf) {
		struct timespec m;
		clock_gettime(CLOCK_MONOTONIC, &m);
		if (!have || m.tv_sec - last >= 60) {
			char b[16] = "";
			FILE *f = fopen(zf, "r");
			if (f) {
				if (fgets(b, sizeof(b), f))
					off = parse_tz(b);
				fclose(f);
			}
			have = 1;
			last = m.tv_sec;
		}
		return off;
	}
	if (!have) {
		off = parse_tz(getenv("LANC_TZ"));
		have = 1;
	}
	return off;
}

// Before Android has set the clock (early boot) the real time is 1970:
// print the time since boot instead, "boot+12.345s".
static void ts(char *buf, size_t n)
{
	struct timespec rt;
	struct tm tm;
	clock_gettime(CLOCK_REALTIME, &rt);
	if (rt.tv_sec < 1577836800) {   // 2020-01-01
		struct timespec bt;
		clock_gettime(CLOCK_BOOTTIME, &bt);
		snprintf(buf, n, "boot+%ld.%03lds", (long)bt.tv_sec, bt.tv_nsec / 1000000);
		return;
	}
	time_t t = rt.tv_sec + tz_off();
	gmtime_r(&t, &tm);
	snprintf(buf, n, "%04d-%02d-%02d %02d:%02d:%02d.%03ld", tm.tm_year + 1900, tm.tm_mon + 1,
		 tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, rt.tv_nsec / 1000000);
}

#define LOG(...) do { char _t[64]; ts(_t, sizeof(_t)); printf("%s ", _t); printf(__VA_ARGS__); printf("\n"); } while (0)

static void pid_comm(uint32_t pid, char *out, size_t n)
{
	char p[64];
	snprintf(out, n, "?");
	if (!pid)
		return;
	snprintf(p, sizeof(p), "/proc/%u/comm", pid);
	FILE *f = fopen(p, "r");
	if (!f)
		return;
	if (fgets(out, n, f))
		out[strcspn(out, "\n")] = 0;
	fclose(f);
}

// Which process owns the netlink socket with this port id? (port ids are
// often not pids). /proc/net/netlink -> inode -> /proc/*/fd.
static void portid_owner(uint32_t portid, char *out, size_t n)
{
	snprintf(out, n, "?");
	FILE *f = fopen("/proc/net/netlink", "r");
	if (!f)
		return;
	char line[512];
	unsigned long inode = 0;
	while (fgets(line, sizeof(line), f)) {
		char sk[64];
		unsigned eth, pid, groups;
		unsigned long rmem, wmem, dump, locks, drops, ino;
		if (sscanf(line, "%63s %u %u %x %lu %lu %lu %lu %lu %lu", sk, &eth, &pid, &groups,
			   &rmem, &wmem, &dump, &locks, &drops, &ino) == 10 && eth == 0 && pid == portid) {
			inode = ino;
			break;
		}
	}
	fclose(f);
	if (!inode)
		return;
	char want[64];
	snprintf(want, sizeof(want), "socket:[%lu]", inode);
	DIR *d = opendir("/proc");
	if (!d)
		return;
	struct dirent *e;
	while ((e = readdir(d))) {
		if (e->d_name[0] < '0' || e->d_name[0] > '9')
			continue;
		char fdp[300];
		snprintf(fdp, sizeof(fdp), "/proc/%s/fd", e->d_name);
		DIR *fd = opendir(fdp);
		if (!fd)
			continue;
		struct dirent *g;
		int found = 0;
		while (!found && (g = readdir(fd))) {
			char lp[600], tgt[64];
			snprintf(lp, sizeof(lp), "%s/%s", fdp, g->d_name);
			ssize_t l = readlink(lp, tgt, sizeof(tgt) - 1);
			if (l > 0) {
				tgt[l] = 0;
				found = !strcmp(tgt, want);
			}
		}
		closedir(fd);
		if (found) {
			char comm[64];
			pid_comm((uint32_t)atoi(e->d_name), comm, sizeof(comm));
			snprintf(out, n, "%s pid %s", comm, e->d_name);
			break;
		}
	}
	closedir(d);
}

static uint64_t mono_us(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * 1000000ull + t.tv_nsec / 1000;
}

// Make sure our filter is on egress; returns 1 if it had to be added.
// create_clsact = 0: never create the clsact qdisc ourselves (someone just
// deleted it and is about to add it again - racing them would make their
// exclusive add fail).
static int ensure_attached(int nl, const char *ifname, int *ifindex, int prog_fd, uint32_t *prog_id, int create_clsact)
{
	int idx = if_nametoindex(ifname);
	if (!idx) {
		*ifindex = 0;
		return 0;
	}
	*ifindex = idx;
	uint32_t id = filter_find(nl, idx, NULL, 0);
	if (id && id == *prog_id)
		return 0;
	uint64_t t0 = mono_us();
	int e = filter_attach(nl, idx, prog_fd);
	if (e < 0) {
		if (!create_clsact)
			return 0;   // no clsact yet - wait for its owner
		e = ensure_clsact(nl, idx);
		if (e < 0) {
			LOG("ERROR clsact %s: %s", ifname, strerror(-e));
			return 0;
		}
		LOG("clsact was missing on %s - created it", ifname);
		e = filter_attach(nl, idx, prog_fd);
		if (e < 0) {
			LOG("ERROR attach %s: %s", ifname, strerror(-e));
			return 0;
		}
	}
	*prog_id = filter_find(nl, idx, NULL, 0);
	LOG("attached %s ifindex=%d prog_id=%u (%llu us)", ifname, idx, *prog_id,
	    (unsigned long long)(mono_us() - t0));
	return 1;
}

#define CLSACT_GRACE_US 500000   // wait this long for the owner to re-add clsact

static void flags_str(unsigned f, char *out, size_t n)
{
	snprintf(out, n, "%s%s%s", (f & IFF_UP) ? "UP" : "DOWN", (f & IFF_LOWER_UP) ? ",LOWER_UP" : "",
		 (f & IFF_RUNNING) ? ",RUNNING" : "");
}

// passive = 1: "monitor" - load nothing, attach nothing, only log the events
static int do_watch(const char *ifname, unsigned flags, const char *logfile, int passive)
{
	// The program is loaded BEFORE the fork: a kernel that refuses it
	// (verifier, no BPF) is reported to the caller as ok=0, not only in the log.
	int nl = nl_open();
	int ifindex = if_nametoindex(ifname);
	int pfd = -1;

	if (!passive) {
		// load once; keep the counters of a program that is already attached
		struct lanc_stats s;
		memset(&s, 0, sizeof(s));
		uint32_t old = ifindex ? filter_find(nl, ifindex, NULL, 0) : 0;
		if (old) {
			int ofd = map_of_prog(old);
			if (ofd >= 0) {
				map_rw(ofd, &s, 0);
				close(ofd);
			}
		}
		s.flags = flags;
		s.abi = LANC_ABI;
		int mfd = map_create(BPF_MAP_TYPE_ARRAY, sizeof(struct lanc_stats), "lanc_stats");
		if (mfd < 0)
			die("map_create", errno);
		if (map_rw(mfd, &s, 1) < 0)
			die("map_update", errno);
		int sfd = map_create(BPF_MAP_TYPE_PERCPU_ARRAY, 24, "lanc_scratch");
		if (sfd < 0)
			die("map_create_scratch", errno);
		pfd = prog_load(mfd, sfd);
		if (pfd < 0)
			die("prog_load", errno);
	}

	if (logfile) {
		int lfd = open(logfile, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
		if (lfd < 0)
			die("log_open", errno);
		pid_t p = fork();
		if (p < 0)
			die("fork", errno);
		if (p > 0) {
			printf("ok=1\npid=%d\n", p);
			char pf[512];
			const char *pe = getenv("LANC_PIDFILE");
			if (pe && *pe)
				snprintf(pf, sizeof(pf), "%s", pe);
			else
				snprintf(pf, sizeof(pf), "%s.pid", logfile);
			FILE *f = fopen(pf, "w");
			if (f) {
				fprintf(f, "%d\n", p);
				fclose(f);
			}
			exit(0);
		}
		setsid();
		int nul = open("/dev/null", O_RDONLY);
		if (nul >= 0) {
			dup2(nul, 0);
			close(nul);
		}
		dup2(lfd, 1);
		dup2(lfd, 2);
		close(lfd);
	}
	signal(SIGTERM, on_term);
	signal(SIGINT, on_term);
	signal(SIGHUP, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);

	// a fresh request socket in the daemon: its port id tells our own
	// changes apart from everyone else's in the event stream
	close(nl);
	nl = nl_open();
	uint32_t my_port = (uint32_t)getpid();
	{
		struct sockaddr_nl me;
		socklen_t ml = sizeof(me);
		if (getsockname(nl, (struct sockaddr *)&me, &ml) == 0)
			my_port = me.nl_pid;
	}

	// event socket: tc + link changes
	int ev = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (ev < 0)
		die("netlink_socket", errno);
	int rb = 1 << 20;
	setsockopt(ev, SOL_SOCKET, SO_RCVBUF, &rb, sizeof(rb));
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK, .nl_groups = RTMGRP_TC | RTMGRP_LINK };
	if (bind(ev, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		die("netlink_bind_events", errno);

	uint32_t prog_id = 0;
	LOG("%s start iface=%s flags=%u pid=%d", passive ? "monitor" : "watch", ifname, flags, getpid());
	if (!passive)
		ensure_attached(nl, ifname, &ifindex, pfd, &prog_id, 1);

	char buf[32768];
	uint64_t gone_since = 0;          // clsact deleted by someone else, not back yet
	unsigned last_lflags = 0xffffffff;
	uint32_t owners[16];
	char owner_what[16][48];
	int nowners = 0;
	uint64_t last_check = mono_us();
	while (!stop_flag) {
		struct pollfd pf = { .fd = ev, .events = POLLIN };
		int r = poll(&pf, 1, (gone_since && !passive) ? 50 : 1000);
		int check = 0;
		if (r > 0) {
			int len = recv(ev, buf, sizeof(buf), MSG_DONTWAIT);
			if (len < 0 && errno == ENOBUFS) {
				LOG("event queue overflow - checking");
				check = 1;
			}
			for (struct nlmsghdr *h = (struct nlmsghdr *)buf; len > 0 && NLMSG_OK(h, (unsigned)len); h = NLMSG_NEXT(h, len)) {
				if (h->nlmsg_type == RTM_NEWLINK || h->nlmsg_type == RTM_DELLINK) {
					struct ifinfomsg *ifi = NLMSG_DATA(h);
					char nm[IF_NAMESIZE] = "";
					int alen = h->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
					for (struct rtattr *a = IFLA_RTA(ifi); RTA_OK(a, alen); a = RTA_NEXT(a, alen))
						if (a->rta_type == IFLA_IFNAME)
							snprintf(nm, sizeof(nm), "%s", (char *)RTA_DATA(a));
					if (strcmp(nm, ifname))
						continue;
					if (h->nlmsg_type == RTM_DELLINK) {
						LOG("link %s removed", ifname);
						last_lflags = 0xffffffff;
						check = 1;
						continue;
					}
					if (ifi->ifi_index != ifindex) {
						LOG("link %s appeared ifindex=%d", ifname, ifi->ifi_index);
						check = 1;
					}
					unsigned lf = ifi->ifi_flags & (IFF_UP | IFF_LOWER_UP | IFF_RUNNING);
					if (lf != last_lflags) {
						char fs[48];
						flags_str(lf, fs, sizeof(fs));
						LOG("link %s %s", ifname, fs);
						// coming up while clsact is still missing: no more waiting,
						// DHCP follows in well under a second
						if ((lf & IFF_UP) && (last_lflags == 0xffffffff || !(last_lflags & IFF_UP)) && gone_since)
							gone_since = 1;   // far in the past = may create now
						last_lflags = lf;
						check = 1;
					}
					continue;
				}
				if (h->nlmsg_type != RTM_NEWQDISC && h->nlmsg_type != RTM_DELQDISC &&
				    h->nlmsg_type != RTM_NEWTFILTER && h->nlmsg_type != RTM_DELTFILTER)
					continue;
				struct tcmsg *t = NLMSG_DATA(h);
				if (!ifindex || t->tcm_ifindex != ifindex)
					continue;
				if (h->nlmsg_pid == my_port)
					continue;   // our own change
				char kind[32] = "";
				int alen = h->nlmsg_len - NLMSG_LENGTH(sizeof(*t));
				for (struct rtattr *a = TCA_RTA(t); RTA_OK(a, alen); a = RTA_NEXT(a, alen))
					if (a->rta_type == TCA_KIND)
						snprintf(kind, sizeof(kind), "%s", (char *)RTA_DATA(a));
				const char *what = h->nlmsg_type == RTM_NEWQDISC ? "qdisc-add" :
						   h->nlmsg_type == RTM_DELQDISC ? "qdisc-del" :
						   h->nlmsg_type == RTM_NEWTFILTER ? "filter-add" : "filter-del";
				const char *dir = t->tcm_parent == TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS) ? "egress" :
						  t->tcm_parent == TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS) ? "ingress" : "";
				if (*dir)
					LOG("event %s %s %s prio=%u by port %u", what, kind, dir, t->tcm_info >> 16, h->nlmsg_pid);
				else
					LOG("event %s %s parent=%x prio=%u by port %u", what, kind, t->tcm_parent,
					    t->tcm_info >> 16, h->nlmsg_pid);
				if (nowners < 16) {
					owners[nowners] = h->nlmsg_pid;
					snprintf(owner_what[nowners], sizeof(owner_what[0]), "%s %s", what, kind);
					nowners++;
				}
				if (!strcmp(kind, "clsact")) {
					if (!strcmp(what, "qdisc-del"))
						gone_since = mono_us();
					else
						gone_since = 0;
				}
				check = 1;
			}
		}
		if (!passive) {
			uint64_t now = mono_us();
			if (now - last_check > 1000000)
				check = 1;
			int may_create = !gone_since || now - gone_since > CLSACT_GRACE_US;
			if (gone_since && may_create)
				check = 1;
			if (check) {
				last_check = now;
				if (ensure_attached(nl, ifname, &ifindex, pfd, &prog_id, may_create) || may_create)
					gone_since = 0;
			}
		} else if (check) {
			int idx = if_nametoindex(ifname);
			if (idx)
				ifindex = idx;
		}
		// after any re-attach: find out who made the changes (slow /proc scan)
		for (int k = 0; k < nowners; k++) {
			char who[400];
			portid_owner(owners[k], who, sizeof(who));
			LOG("  port %u (%s) = %s", owners[k], owner_what[k], who);
		}
		nowners = 0;
	}
	if (!passive) {
		int idx = if_nametoindex(ifname);
		if (idx && filter_find(nl, idx, NULL, 0) == prog_id)
			filter_detach(nl, idx);
		LOG("watch stop - filter removed");
	} else {
		LOG("monitor stop");
	}
	return 0;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc >= 2 && !strcmp(argv[1], "version")) {
		printf("lanc-bpf abi=%d\n", LANC_ABI);
		return 0;
	}
	if (argc < 3) {
		fprintf(stderr, "usage: lanc-bpf attach|set|watch <iface> <flags> [log] | monitor <iface> [log] | detach|status|check <iface> | version\n");
		return 2;
	}
	const char *cmd = argv[1], *ifname = argv[2];
	int ifindex = if_nametoindex(ifname);
	int nl = nl_open();

	if (!strcmp(cmd, "check")) {   // can this kernel run the program? (load, no attach)
		int mfd = map_create(BPF_MAP_TYPE_ARRAY, sizeof(struct lanc_stats), "lanc_stats");
		if (mfd < 0)
			die("map_create", errno);
		int sfd = map_create(BPF_MAP_TYPE_PERCPU_ARRAY, 24, "lanc_scratch");
		if (sfd < 0)
			die("map_create_scratch", errno);
		int pfd = prog_load(mfd, sfd);
		if (pfd < 0)
			die("prog_load", errno);
		printf("ok=1\n");
		return 0;
	}

	if (!strcmp(cmd, "status")) {
		printf("iface=%s\n", ifname);
		if (!ifindex) {
			printf("iface_present=0\nattached=0\n");
			return 0;
		}
		char name[64] = "";
		uint32_t id = filter_find(nl, ifindex, name, sizeof(name));
		printf("iface_present=1\nattached=%d\nprog_id=%u\nfilter_name=%s\n", id ? 1 : 0, id, name);
		if (!id)
			return 0;
		int mfd = map_of_prog(id);
		struct lanc_stats s;
		memset(&s, 0, sizeof(s));
		if (mfd < 0 || map_rw(mfd, &s, 0) < 0) {
			printf("stats=0\n");
			return 0;
		}
		uint64_t now = boot_ns();
		printf("stats=1\nflags=%u\nabi=%u\nseen=%llu\nchanged=%llu\nskipped=%llu\nhost=%llu\nvendor=%llu\nprl=%llu\n",
		       s.flags, s.abi, (unsigned long long)s.seen, (unsigned long long)s.changed,
		       (unsigned long long)s.skipped, (unsigned long long)s.host,
		       (unsigned long long)s.vendor, (unsigned long long)s.prl);
		age("last_seen_age", s.last_seen, now);
		age("last_changed_age", s.last_changed, now);
		return 0;
	}

	if (!strcmp(cmd, "detach")) {
		if (!ifindex) {
			printf("ok=1\nremoved=0\nnote=no-interface\n");
			return 0;
		}
		int e = filter_detach(nl, ifindex);
		if (e < 0)
			die("filter_delete", -e);
		printf("ok=1\nremoved=%d\n", e == 0 ? 1 : 0);
		return 0;
	}

	if (!strcmp(cmd, "watch") && argc >= 4)
		return do_watch(ifname, parse_flags(argv[3]), argc >= 5 ? argv[4] : NULL, 0);
	if (!strcmp(cmd, "monitor"))
		return do_watch(ifname, 0, argc >= 4 ? argv[3] : NULL, 1);

	if ((!strcmp(cmd, "attach") || !strcmp(cmd, "set")) && argc >= 4) {
		unsigned flags = parse_flags(argv[3]);
		if (!ifindex)
			die("no_interface", ENODEV);
		if (!strcmp(cmd, "set")) {
			uint32_t id = filter_find(nl, ifindex, NULL, 0);
			int mfd = id ? map_of_prog(id) : -1;
			struct lanc_stats s;
			if (mfd < 0 || map_rw(mfd, &s, 0) < 0)
				die("not_attached", ENOENT);
			s.flags = flags;   // counters keep running (tiny race is harmless)
			if (map_rw(mfd, &s, 1) < 0)
				die("map_update", errno);
			printf("ok=1\nprog_id=%u\nflags=%u\n", id, flags);
			return 0;
		}
		// attach: keep the counters of a running program
		struct lanc_stats s;
		memset(&s, 0, sizeof(s));
		uint32_t old = filter_find(nl, ifindex, NULL, 0);
		if (old) {
			int ofd = map_of_prog(old);
			if (ofd >= 0) {
				map_rw(ofd, &s, 0);
				close(ofd);
			}
		}
		s.flags = flags;
		s.abi = LANC_ABI;
		int mfd = map_create(BPF_MAP_TYPE_ARRAY, sizeof(struct lanc_stats), "lanc_stats");
		if (mfd < 0)
			die("map_create", errno);
		if (map_rw(mfd, &s, 1) < 0)
			die("map_update", errno);
		int sfd = map_create(BPF_MAP_TYPE_PERCPU_ARRAY, 24, "lanc_scratch");
		if (sfd < 0)
			die("map_create_scratch", errno);
		int pfd = prog_load(mfd, sfd);
		if (pfd < 0)
			die("prog_load", errno);
		int e = ensure_clsact(nl, ifindex);
		if (e < 0)
			die("clsact", -e);
		e = filter_attach(nl, ifindex, pfd);
		if (e < 0)
			die("filter_add", -e);
		uint32_t id = filter_find(nl, ifindex, NULL, 0);
		if (!id)
			die("filter_not_found_after_add", ENOENT);
		printf("ok=1\nprog_id=%u\nflags=%u\nreplaced=%d\n", id, flags, old ? 1 : 0);
		return 0;
	}
	fprintf(stderr, "unknown command\n");
	return 2;
}
