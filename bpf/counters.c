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

// There are two races that we should be aware of: 1) multiple threads
// accessing the same value, or 2) use space and kernel space accessing
// the same value.
// Per-CPU-Arrays solve the first problem for us but not the second.
// Since user space will only ever read these counters we can allow
// the race to happen and sacrifice some precision.
//
// https://docs.ebpf.io/linux/concepts/concurrency/
// https://docs.kernel.org/bpf/map_array.html#kernel-bpf

static __always_inline void update_counters(struct xdp_md *ctx, __u32 key)
{
    __u64 *counter;
    
    counter = bpf_map_lookup_elem(&packet_counters, &key);
    if (counter) {
        // TODO: re-evaluate the need for __sync_fetch_and_add
        // __sync_fetch_and_add(counter, 1);
        (*counter)++;
    }
    
    counter = bpf_map_lookup_elem(&byte_counters, &key);
    if (counter) {
        // TODO: re-evaluate the need for __sync_fetch_and_add
        // __sync_fetch_and_add(counter, ctx->data_end - ctx->data);
        (*counter)+=ctx->data_end - ctx->data;
    }
}

#define MAX_INTERFACES 16

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_INTERFACES);
    __array(values, struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key, __u32);
        __type(value, __u64);
        __uint(max_entries, MAX_INTERFACES);
    });
} interface_packet_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_INTERFACES);
    __array(values, struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key, __u32);
        __type(value, __u64);
        __uint(max_entries, MAX_COUNTERS);
    });
} interface_byte_counters SEC(".maps");

static __always_inline void update_counters_2(struct xdp_md *ctx, __u32 key)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u32 ifindex = ctx->ingress_ifindex;
    __u64 *counter;
    void *inner;
    __u64 pkt_len;

    pkt_len = data_end - data;

    inner = bpf_map_lookup_elem(&interface_packet_counters, &ifindex);
    if (!inner)
        return;

    counter = bpf_map_lookup_elem(inner, &key);
    if (counter)
        // TODO: re-evaluate the need for __sync_fetch_and_add
        // __sync_fetch_and_add(counter, 1);
        (*counter)++;

    inner = bpf_map_lookup_elem(&interface_byte_counters, &ifindex);
    if (!inner)
        return;

    counter = bpf_map_lookup_elem(inner, &key);
    if (counter)
        // TODO: re-evaluate the need for __sync_fetch_and_add
        // __sync_fetch_and_add(counter, pkt_len);
        (*counter)+=pkt_len;

    return;
}
