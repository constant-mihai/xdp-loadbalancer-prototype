//go:build ignore

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

enum counter_index {
    INGRESS_IDX = 0,
    EGRESS_IDX = 1,
    PASSED_IDX = 2,
    DROP_IDX = 3,
    
    MAX_COUNTERS = 4
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

static __always_inline void update_counters(struct xdp_md *ctx, __u32 key)
{
    __u64 *counter;
    
    counter = bpf_map_lookup_elem(&packet_counters, &key);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
    
    counter = bpf_map_lookup_elem(&byte_counters, &key);
    if (counter) {
        __sync_fetch_and_add(counter, ctx->data_end - ctx->data);
    }
}

