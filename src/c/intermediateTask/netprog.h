#ifndef __NETPROG_H
#define __NETPROG_H

#include <linux/types.h>

struct dns_query_key {
    __u8 ip_version;
    __u8 pad;             
    __u16 dns_id;
    __u32 src_ip4;
    __u8 src_ip6[16];
};

#endif
