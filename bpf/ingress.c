//go:build ignore

#include "vmlinux.h"
// TODO: why can't this find asm/types.h?
// #include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int ingress(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    update_counters_2(ctx, INGRESS_IDX);

pass:
    update_counters_2(ctx, PASSED_IDX);
    return XDP_PASS;
drop:
    update_counters_2(ctx, DROP_IDX);
    return XDP_DROP;
}
