// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "netprog.h"

char _license[] SEC("license") = "Dual BSD/GPL";

#define DNS_PORT 53
#define MAX_BUCKETS 30
#define MAX_RTT_NS 500000000ULL    // 0.5 second

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct dns_query_key);
    __type(value, __u64);
    __uint(max_entries, 1024);
} dns_query_ts_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, MAX_BUCKETS);
} rtt_histogram SEC(".maps");

static __always_inline __u32 log2_bucket(__u64 latency_ns) {
    __u32 i = 0;
    latency_ns >>= 1;
    while (latency_ns > 0 && i < MAX_BUCKETS - 1) {
        latency_ns >>= 1;
        i++;
    }
    return i;
}

static __always_inline int handle_dns_packet(void *data, void *data_end, int ip_version, __u16 dns_id, void *ip_ptr, __u8 is_response) {
    struct dns_query_key key = {};
    key.ip_version = ip_version;
    key.pad = 0;
    key.dns_id = dns_id;

    if (ip_version == 4) {
        key.src_ip4 = *(__u32 *)ip_ptr;
    } else {
        __builtin_memcpy(&key.src_ip6, ip_ptr, 16);
    }

    __u64 now = bpf_ktime_get_ns();

    if (!is_response) {
        bpf_map_update_elem(&dns_query_ts_map, &key, &now, BPF_ANY);
    } else {
        __u64 *tsp = bpf_map_lookup_elem(&dns_query_ts_map, &key);
        if (tsp) {
            __u64 delta = now - *tsp;
            if (delta <= MAX_RTT_NS) {
                __u32 bucket = log2_bucket(delta);
                __u64 *count = bpf_map_lookup_elem(&rtt_histogram, &bucket);
                if (count)
                    __sync_fetch_and_add(count, 1);
            }
            bpf_map_delete_elem(&dns_query_ts_map, &key);
        }
    }

    return XDP_PASS;
}

SEC("xdp")
int xdp_dns_latency(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = bpf_ntohs(eth->h_proto);
    void *nh = data + sizeof(*eth);

    if (h_proto == ETH_P_IP) {
        struct iphdr *ip = nh;
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end || ip->protocol != IPPROTO_UDP)
            return XDP_PASS;

        if (bpf_ntohs(udp->source) != DNS_PORT && bpf_ntohs(udp->dest) != DNS_PORT)
            return XDP_PASS;

        __u8 *dns = (void *)(udp + 1);
        if ((void *)(dns + 12) > data_end)
            return XDP_PASS;

        __u16 dns_id = ((__u16)dns[0] << 8) | dns[1];
        __u8 flags = dns[2];
        __u8 is_response = flags >> 7;

        void *ip_ptr = is_response ? &ip->daddr : &ip->saddr;
        return handle_dns_packet(dns, data_end, 4, dns_id, ip_ptr, is_response);

    } else if (h_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = nh;
        if ((void *)(ip6 + 1) > data_end || ip6->nexthdr != IPPROTO_UDP)
            return XDP_PASS;

        struct udphdr *udp = (void *)(ip6 + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        if (bpf_ntohs(udp->source) != DNS_PORT && bpf_ntohs(udp->dest) != DNS_PORT)
            return XDP_PASS;

        __u8 *dns = (void *)(udp + 1);
        if ((void *)(dns + 12) > data_end)
            return XDP_PASS;

        __u16 dns_id = ((__u16)dns[0] << 8) | dns[1];
        __u8 flags = dns[2];
        __u8 is_response = flags >> 7;

        void *ip_ptr = is_response ? &ip6->daddr : &ip6->saddr;
        return handle_dns_packet(dns, data_end, 6, dns_id, ip_ptr, is_response);
    }

    return XDP_PASS;
}
