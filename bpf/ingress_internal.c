//go:build ignore

#include "vmlinux.h"
// TODO: why can't this find asm/types.h?
// #include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int ingress_external(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

pass:
    update_counters(ctx, PASSED_IDX);
    return XDP_PASS;
drop:
    update_counters(ctx, DROP_IDX);
    return XDP_DROP;
}
