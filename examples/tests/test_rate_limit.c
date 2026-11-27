// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

#include "../rate_limit.c"
#include "harness.h"

static struct h_addr a, b;

static uint64_t send_from(struct h_addr src) {
    h_build_udp(src, 40000, h_ipv4(192, 0, 2, 10), 7777, "x", 1);
    return h_run();
}

int main(void) {
    harness_reset();
    a = h_ipv4(198, 51, 100, 1);
    b = h_ipv4(198, 51, 100, 2);

    /* The first RATE_LIMIT packets in a window pass, the next one drops. */
    int passed = 0;
    for (int i = 0; i < RATE_LIMIT; i++) passed += send_from(a) == CF_EBPF_PASS;
    CHECK_EQ(passed, RATE_LIMIT);
    CHECK_EQ(send_from(a), CF_EBPF_DROP);
    CHECK_EQ(send_from(a), CF_EBPF_DROP);
    CHECK_EQ(STATE_COUNT(h_src_entry_for(a)->data), RATE_LIMIT);

    /* Another source IP has its own budget. */
    CHECK_EQ(send_from(b), CF_EBPF_PASS);

    /* Still limited just before the window ends. */
    h_now += WINDOW_SECONDS - 1;
    CHECK_EQ(send_from(a), CF_EBPF_DROP);

    /* A new window starts once WINDOW_SECONDS have passed. */
    h_now += 1;
    CHECK_EQ(send_from(a), CF_EBPF_PASS);
    CHECK_EQ(STATE_COUNT(h_src_entry_for(a)->data), 1);
    CHECK_EQ(STATE_START(h_src_entry_for(a)->data), (uint32_t)h_now);

    /* Fail open when the source IP state table is not enabled. */
    harness_reset();
    h_src_state_enabled = 0;
    for (int i = 0; i < RATE_LIMIT + 5; i++) CHECK_EQ(send_from(a), CF_EBPF_PASS);

    return harness_finish("rate_limit");
}
