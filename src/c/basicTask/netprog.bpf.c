// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>         // definisce IPPROTO_UDP
#include <bpf/bpf_endian.h>   // definisce bpf_ntohs()
#include "netprog.h"

#define DNS_PORT 53

/* la struct definisce una mappa hash:
	•	Chiave: struct dns_query_key → include ID DNS + IP sorgente.
	•	Valore: __u64 → timestamp in nanosecondi.
	•	Usata per salvare il momento esatto della richiesta DNS.
*/

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct dns_query_key);
    __type(value, __u64);
    __uint(max_entries, 1024);
} dns_query_ts_map SEC(".maps");

/*Entry-point del programma. Viene eseguito ogni volta che un pacchetto passa per l’interfaccia monitorata da XDP.*/
SEC("xdp")
int xdp_dns_latency(struct xdp_md *ctx) {
    //Estrae puntatori all’inizio e alla fine dei dati del pacchetto (per verifiche bounds-safe).
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Legge header Ethernet e verifica che non sfori i limiti del pacchetto.
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Ottiene tipo di protocollo (IPv4, IPv6, ecc.) e avanza il puntatore alla prossima intestazione (IP).
    __u16 h_proto = bpf_ntohs(eth->h_proto);
    void *nh = data + sizeof(*eth);

    //Verifica che sia IPv4 e protocollo UDP
    if (h_proto == ETH_P_IP) {
        struct iphdr *ip = nh;
        if ((void *)(ip + 1) > data_end || ip->protocol != IPPROTO_UDP)
            return XDP_PASS;

            //Estrae header UDP e controlla se la porta di destinazione è 53 (DNS).
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        if (bpf_ntohs(udp->dest) != DNS_PORT)
            return XDP_PASS;


        // Verifica che il payload DNS contenga almeno 2 byte (per l’ID transazione DNS).

        __u8 *dns = (void *)(udp + 1);
        if (dns + 2 > (unsigned char *)data_end)
            return XDP_PASS;

        // salva i dati nella struttura
        struct dns_query_key key = {};
        key.ip_version = 4;
        key.dns_id = ((__u16)dns[0] << 8) | dns[1];
        key.src_ip4 = ip->saddr;

        __u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&dns_query_ts_map, &key, &ts, BPF_ANY);
        return XDP_PASS;
    } else if (h_proto == ETH_P_IPV6) {
        // questo è il caso del protocollo IPv6
        struct ipv6hdr *ip6 = nh;
        if ((void *)(ip6 + 1) > data_end || ip6->nexthdr != IPPROTO_UDP)
            return XDP_PASS;

        struct udphdr *udp = (void *)(ip6 + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        if (bpf_ntohs(udp->dest) != DNS_PORT)
            return XDP_PASS;

        __u8 *dns = (void *)(udp + 1);
        if (dns + 2 > (unsigned char *)data_end)
            return XDP_PASS;

        struct dns_query_key key = {};
        key.ip_version = 6;
        key.dns_id = ((__u16)dns[0] << 8) | dns[1];
        __builtin_memcpy(&key.src_ip6, &ip6->saddr, 16);

        __u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&dns_query_ts_map, &key, &ts, BPF_ANY);
        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
