/* SPDX-License-Identifier: GPL-2.0 */
#include <vmlinux.h>
#include <errno.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ETH_P_IPV6		0x86DD	/* IPv6 */
#define IPPROTO_ICMPV6		58	/* ICMPv6 */


/* Byte-count bounds check; check if current pointer at @start + @off of header
 * is after @end.
 */
#define __may_pull(start, off, end) \
	(((unsigned char *)(start)) + (off) <= ((unsigned char *)(end)))

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

struct proc_stats {
	__u64 drop;
};

#define XDP_STATS_MAP_NELEM_MAX 1
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct proc_stats);
	__uint(max_entries, XDP_STATS_MAP_NELEM_MAX);
} xdp_stats_map SEC(".maps");

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

SEC("xdp")
int  xdp_prog_pass(struct xdp_md *ctx)
{
	return XDP_PASS;
}

static __always_inline int
parse_ethhdr(struct hdr_cursor *nh, void *data_end, struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);
	__u16 h_proto;

	if (!__may_pull(eth, hdrsize, data_end))
		return -EINVAL;

	/* Move the cursor ahead as we have parsed the ethernet header */
	nh->pos += hdrsize;
	/* network-byte-order */
	h_proto = eth->h_proto;

	if (ethhdr)
		*ethhdr = eth;

	return h_proto;
}

static __always_inline int
parse_ip6hdr(struct hdr_cursor *nh, void *data_end, struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = nh->pos;
	int hdrsize = sizeof(*ip6h);

	/* Pointer-arithmetic bounds check; pointer +1 points to after end of
	 * thing being pointed to.
	 */
	if (!__may_pull(ip6h, hdrsize, data_end))
		return -EINVAL;

	nh->pos += hdrsize;

	if (ip6hdr)
		*ip6hdr = ip6h;

	return ip6h->nexthdr;
}

static __always_inline int
process_ipv6hdr(struct hdr_cursor *nh, void *data_end)
{
	struct proc_stats *pstats;
	struct ipv6hdr *ip6h;
	const int key = 0;
	int nexthdr;

	nexthdr = parse_ip6hdr(nh, data_end, &ip6h);
	if (nexthdr < 0)
		return XDP_PASS;

	/* Do processing based on the IPv6 next header. In this specific case,
	 * drop any ICMPv6 packet.
	 */
	if (nexthdr != IPPROTO_ICMPV6)
		return XDP_PASS;

	/* Lookup in kernel BPF-side return pointer to stats record */
	pstats = bpf_map_lookup_elem(&xdp_stats_map, &key);
	if (!pstats) {
		/* BPF kernel-side verifier will reject program if the
		 * NULL pointer check isn't performed here. Even-though
		 * this is a static array where we know key lookup
		 * XDP_PASS always will succeed.
		 */
		bpf_printk("XDP: Cannot access to proc stats, weird!?! Abort!");
		return XDP_ABORTED;
	}


	/* Multiple CPUs can access data record. Thus, the accounting needs to
	 * use an atomic operation.
	 */
	lock_xadd(&pstats->drop, 1);

	bpf_printk("XDP: received ICMPv6 packet! Drop it!");
	return XDP_DROP;
}

SEC("xdp")
int  xdp_prog_drop_icmpv6(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int h_proto;
       __u16 proto;

	/* These keep track of the next header type and interator pointer */
	nh.pos = data;

	h_proto = parse_ethhdr(&nh, data_end, &eth);
	if (h_proto < 0)
		/* we cannot parse the ethernet header; instead of droppig the
		 * packet we allow it to go in the kernel networking stack to
		 * be further processed.
		 */
		goto out;

	/* From network-byte-order to machine endianess */
	proto = bpf_ntohs(h_proto);
	switch (proto) {
	case ETH_P_IPV6:
		return process_ipv6hdr(&nh, data_end);
	};

	/* Pass the packet to the upper kernel networking */
out:
	return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
