//go:build ignore

#include "vmlinux.h"
// TODO: why can't this find asm/types.h?
// #include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define ETH_P_IP 0x0800

struct foo {
    __u32 a;
};

// TODO: I would like to have separate counters for every interface.
enum counter_index {
    INGRESS_IDX = 0,
    EGRESS_IDX = 1,
    DROP_IDX = 2,
    
    MAX_COUNTERS = 3
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_COUNTERS);
    __type(key, __u32);
    __type(value, __u64);
} packet_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_COUNTERS);
    __type(key, __u32);
    __type(value, __u64);
} byte_counters SEC(".maps");

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
    __u32 key = INGRESS_IDX;
    __u64 *counter;
    
    counter = bpf_map_lookup_elem(&packet_counters, &key);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }

    counter = bpf_map_lookup_elem(&byte_counters, &key);
    if (counter) {
        __sync_fetch_and_add(counter, ctx->data_end - ctx->data);
    }
done:
	// Try changing this to XDP_DROP and see what happens!
	return XDP_PASS;
}
