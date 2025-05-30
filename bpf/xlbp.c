//go:build ignore

#include "vmlinux.h"
// TODO: why can't this find asm/types.h?
// #include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "counters.c"
#include "ingress_external.c"
#include "ingress_internal.c"

#define AF_INET 2
#define AF_INET6 10

static __always_inline __u32 swab32(u32 x)
{
	return  ((x & (u32)0x000000ffUL) << 24) |
		((x & (u32)0x0000ff00UL) <<  8) |
		((x & (u32)0x00ff0000UL) >>  8) |
		((x & (u32)0xff000000UL) >> 24);
}

#define cpu_to_be32(x) swab32(x)
#define IPV6_FLOWINFO_MASK		cpu_to_be32(0x0FFFFFFF)

char __license[] SEC("license") = "Dual MIT/GPL";

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_ALEN 6


#define MAX_SERVICES 512

// services_by_index_value will store the service ipv4 in network byte order.
struct services_by_index_value {
    __u32 ipv4;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SERVICES);
    __type(key, __u32);
    __type(value, struct services_by_index_value);
} services_by_index SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} round_robin_index SEC(".maps");

// conntrack will map all flows going to services
// behind the load balancer.
struct conntrack_key {
    __u32 src_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
};

struct conntrack_value {
    __u32 service_index;
    __u16 natted_src_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct conntrack_key);
    __type(value, struct conntrack_value);
} conntrack SEC(".maps");

// xdp_tx_ports represent the source ports used to send traffic
// to the internal services.
struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 64);
} xdp_tx_ports SEC(".maps");

static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	u32 check = iph->check;

	check += bpf_htons(0x0100);
	iph->check = (check + (check >= 0xFFFF));
	return --iph->ttl;
}

#undef bpf_printk
#define bpf_printk(fmt, ...)                            \
({                                                      \
        static const char ____fmt[] = fmt;              \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

// /store/repos/linux/samples/bpf/xdp_fwd_kern.c
static __always_inline int xdp_fwd_flags(struct xdp_md *ctx, u32 flags)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_fib_lookup fib_params;
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;
	u16 h_proto;
	u64 eth_size;
	int rc;

	eth_size = sizeof(*eth);
	if (data + eth_size > data_end)
		return XDP_DROP;

	__builtin_memset(&fib_params, 0, sizeof(fib_params));

	h_proto = eth->h_proto;
	if (h_proto == bpf_htons(ETH_P_IP)) {
		iph = data + eth_size;

		if ((void*)(iph + 1) > data_end)
			return XDP_DROP;

		if (iph->ttl <= 1)
			return XDP_PASS;

		fib_params.family	= AF_INET;
		fib_params.tos		= iph->tos;
		fib_params.l4_protocol	= iph->protocol;
		fib_params.sport	= 0;
		fib_params.dport	= 0;
		fib_params.tot_len	= bpf_ntohs(iph->tot_len);
		fib_params.ipv4_src	= iph->saddr;
		fib_params.ipv4_dst	= iph->daddr;
	} else if (h_proto == bpf_htons(ETH_P_IPV6)) {
		struct in6_addr *src = (struct in6_addr *) fib_params.ipv6_src;
		struct in6_addr *dst = (struct in6_addr *) fib_params.ipv6_dst;

		ip6h = data + eth_size;
		if ((void*)(ip6h + 1) > data_end)
			return XDP_DROP;

		if (ip6h->hop_limit <= 1)
			return XDP_PASS;

		fib_params.family	= AF_INET6;
		fib_params.flowinfo	= *(__be32 *)ip6h & IPV6_FLOWINFO_MASK;
		fib_params.l4_protocol	= ip6h->nexthdr;
		fib_params.sport	= 0;
		fib_params.dport	= 0;
		fib_params.tot_len	= bpf_ntohs(ip6h->payload_len);
		*src			= ip6h->saddr;
		*dst			= ip6h->daddr;
        return XDP_DROP;
	} else {
		return XDP_PASS;
	}

    __u8 b0 = iph->daddr >> 24;
    __u8 b1 = iph->daddr >> 16;
    __u8 b2 = iph->daddr >> 8;
    __u8 b3 = iph->daddr;
    bpf_printk("Destination IP: %d", b0);
    bpf_printk("Destination IP: %d", b1);
    bpf_printk("Destination IP: %d", b2);
    bpf_printk("Destination IP: %d", b3);
    // TODO: i need to use the egress interface index.
	fib_params.ifindex = ctx->ingress_ifindex;

	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), flags);

    bpf_printk("look up %d", rc);
	/*
	 * Some rc (return codes) from bpf_fib_lookup() are important,
	 * to understand how this XDP-prog interacts with network stack.
	 *
	 * BPF_FIB_LKUP_RET_NO_NEIGH:
	 *  Even if route lookup was a success, then the MAC-addresses are also
	 *  needed.  This is obtained from arp/neighbour table, but if table is
	 *  (still) empty then BPF_FIB_LKUP_RET_NO_NEIGH is returned.  To avoid
	 *  doing ARP lookup directly from XDP, then send packet to normal
	 *  network stack via XDP_PASS and expect it will do ARP resolution.
	 *
	 * BPF_FIB_LKUP_RET_FWD_DISABLED:
	 *  The bpf_fib_lookup respect sysctl net.ipv{4,6}.conf.all.forwarding
	 *  setting, and will return BPF_FIB_LKUP_RET_FWD_DISABLED if not
	 *  enabled this on ingress device.
	 */
	if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
		/* Verify egress index has been configured as TX-port.
		 * (Note: User can still have inserted an egress ifindex that
		 * doesn't support XDP xmit, which will result in packet drops).
		 *
		 * Note: lookup in devmap supported since 0cdbb4b09a0.
		 * If not supported will fail with:
		 *  cannot pass map_type 14 into func bpf_map_lookup_elem#1:
		 */
        bpf_printk("look up tx port for ifc idx: %d", fib_params.ifindex);
		if (!bpf_map_lookup_elem(&xdp_tx_ports, &fib_params.ifindex)) {
            bpf_printk("no tx port");
			return XDP_PASS;
        }

		if (h_proto == bpf_htons(ETH_P_IP))
			ip_decrease_ttl(iph);
		else if (h_proto == bpf_htons(ETH_P_IPV6))
			ip6h->hop_limit--;

		__builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
		__builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
		return bpf_redirect_map(&xdp_tx_ports, fib_params.ifindex, 0);
	}

	return XDP_PASS;
}

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	return ~((csum & 0xffff) + (csum >> 16));
}

static __always_inline void ipv4_csum(void *data_start, int data_size,
				      __u32 *csum)
{
	*csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
	*csum = csum_fold_helper(*csum);
}

static __always_inline int get_ports(struct iphdr *iph, void *data_end, __u16 *src_port, __u16* dst_port, __u8 *protocol)
{
    switch(iph->protocol){
    case IPPROTO_TCP: {
        *protocol = IPPROTO_TCP;
        struct tcphdr *tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);
        if ((void *)(tcph + 1) > data_end)
            return XDP_DROP;
        *src_port = bpf_ntohs(tcph->source);
        *dst_port = bpf_ntohs(tcph->dest);
                      }
    case IPPROTO_UDP: {
        *protocol = IPPROTO_UDP;
        struct udphdr *udph = (struct udphdr *)((void *)iph + iph->ihl * 4);
        if ((void *)(udph + 1) > data_end)
            return XDP_DROP;
        *src_port = bpf_ntohs(udph->source);
        *dst_port = bpf_ntohs(udph->dest);
                      }
    default:
        return XDP_PASS;
    }
}

SEC("xdp")
int load_balance(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct bpf_fib_lookup fib_params;
    __builtin_memset(&fib_params, 0, sizeof(fib_params));

    update_counters(ctx, INGRESS_IDX);
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        goto drop;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        goto drop;
    
    if (iph->ttl <= 1)
        return XDP_PASS;

    // Extract port information based on protocol
    __u16 src_port = 0, dst_port = 0;
    __u8 protocol = 0;

    if (get_ports(iph, data_end, &src_port, &dst_port, &protocol) == XDP_DROP)
        goto drop;

    // Create connection key
    struct conntrack_key ckey = {
        .src_ip = iph->saddr,
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = protocol
    };

    struct conntrack_value *cval = bpf_map_lookup_elem(&conntrack, &ckey);
    
    if (cval) {
        __u32 skey = 0;
        struct services_by_index_value *sval = bpf_map_lookup_elem(&services_by_index, &skey);
        if (sval) {
            // Update destination IP
            iph->daddr = sval->ipv4;

            // TODO: select random port and change the source port with something read from xdp_tx_ports
            // right now xdp_fwd_flags is doing a lookup on xdp_tx_ports.
            // xdp_tx_ports is storing a port number at ifindex. 
            // tcph->dest = cval->natted_src_port; 
        }
    } else {
        // New connection, select an service via round robin.
        __u32 rr_key = 0;
        __u32 *rr_idx = bpf_map_lookup_elem(&round_robin_index, &rr_key);
        if (!rr_idx) {
            goto drop;
        }

        // rr_idx will wrap, but that's ok, it's meant to be used as a modulo anyway.
        __sync_fetch_and_add(rr_idx, 1);
        // TODO: how do I keep the number of num services that are in the map?
        // hardcode 3 for now.
        __u32 skey = (*rr_idx) % 3;
        struct services_by_index_value *svalue = bpf_map_lookup_elem(&services_by_index, &skey);
        if (!svalue) {
            goto drop;
        }

        struct conntrack_value new_cval = { .service_index = skey };
        bpf_map_update_elem(&conntrack, &ckey, &new_cval, BPF_ANY);
        
        iph->daddr = svalue->ipv4;
    }

    // Recalculate IP checksum
    __u32 csum = 0;
    ipv4_csum(iph, sizeof(struct iphdr), &csum);
    iph->check = csum;

    // TODO: TCP and UPD check sums? What happens in xdp_fwd_flags when the
    // packet is forwarded?
    int ret = xdp_fwd_flags(ctx, BPF_FIB_LOOKUP_DIRECT);
    if (ret == XDP_DROP)
        goto drop;

	return XDP_PASS;
drop:
    update_counters(ctx, DROP_IDX);
    return XDP_DROP;
}
