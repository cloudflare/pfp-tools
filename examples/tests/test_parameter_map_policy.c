// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

#include "../parameter_map_policy.c"
#include "harness.h"

static uint64_t send_from(struct h_addr src) {
    struct h_addr dst = src.family == 4 ? h_ipv4(192, 0, 2, 10) : h_ipv6_doc(10);
    h_build_udp(src, 40000, dst, 443, "hello", 5);
    return h_run();
}

int main(void) {
    struct h_addr blocked4 = h_ipv4(192, 0, 2, 1);
    struct h_addr allowed4 = h_ipv4(192, 0, 2, 2);
    struct h_addr unknown4 = h_ipv4(198, 51, 100, 9);
    struct h_addr blocked6 = h_ipv6_doc(1);
    struct h_addr unknown6 = h_ipv6_doc(9);

    harness_reset();
    h_param_define(PARAM_SOURCE_POLICY_V4, 4, 1);
    h_param_set(PARAM_SOURCE_POLICY_V4, blocked4, POLICY_BLOCK);
    h_param_set(PARAM_SOURCE_POLICY_V4, allowed4, POLICY_ALLOW);
    h_param_define(PARAM_SOURCE_POLICY_V6, 16, 1);
    h_param_set(PARAM_SOURCE_POLICY_V6, blocked6, POLICY_BLOCK);

    CHECK_EQ(send_from(blocked4), CF_EBPF_DROP);
    CHECK_EQ(send_from(allowed4), CF_EBPF_PASS);
    CHECK_EQ(send_from(unknown4), CF_EBPF_PASS);
    CHECK_EQ(send_from(blocked6), CF_EBPF_DROP);
    CHECK_EQ(send_from(unknown6), CF_EBPF_PASS);

    /* Maps swapped (IPv6 keys in map 0): -4, fail open. */
    harness_reset();
    h_param_define(PARAM_SOURCE_POLICY_V4, 16, 1);
    CHECK_EQ(send_from(blocked4), CF_EBPF_PASS);

    /* Value wider than the program's buffer (u16 map): -3, fail open. */
    harness_reset();
    h_param_define(PARAM_SOURCE_POLICY_V4, 4, 2);
    h_param_set(PARAM_SOURCE_POLICY_V4, blocked4, POLICY_BLOCK);
    CHECK_EQ(send_from(blocked4), CF_EBPF_PASS);

    /* No maps configured (-7) and feature not enabled (-5): fail open. */
    harness_reset();
    CHECK_EQ(send_from(blocked4), CF_EBPF_PASS);
    h_params_enabled = 0;
    CHECK_EQ(send_from(blocked4), CF_EBPF_PASS);

    return harness_finish("parameter_map_policy");
}
