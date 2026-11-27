// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

#include "../flow_handshake.c"
#include "harness.h"

static struct h_addr client, server;

static uint64_t send_msg(uint16_t sport, uint8_t type) {
    uint8_t payload[4] = {type, 0, 0, 0};
    h_build_udp(client, sport, server, GAME_PORT, payload, sizeof(payload));
    return h_run();
}

int main(void) {
    harness_reset();
    client = h_ipv4(198, 51, 100, 1);
    server = h_ipv4(192, 0, 2, 10);

    /* Data before CONNECT is dropped. */
    CHECK_EQ(send_msg(40000, 2), CF_EBPF_DROP);

    /* CONNECT opens the flow, then data passes. */
    CHECK_EQ(send_msg(40000, MSG_CONNECT), CF_EBPF_PASS);
    CHECK_EQ(send_msg(40000, 2), CF_EBPF_PASS);

    /* A different source port is a different flow. */
    CHECK_EQ(send_msg(40001, 2), CF_EBPF_DROP);

    /* Activity keeps the flow open. */
    h_now += IDLE_TIMEOUT_SECONDS;
    CHECK_EQ(send_msg(40000, 2), CF_EBPF_PASS);

    /* An idle flow must reconnect. */
    h_now += IDLE_TIMEOUT_SECONDS + 1;
    CHECK_EQ(send_msg(40000, 2), CF_EBPF_DROP);
    CHECK_EQ(send_msg(40000, MSG_CONNECT), CF_EBPF_PASS);
    CHECK_EQ(send_msg(40000, 2), CF_EBPF_PASS);

    /* Empty payloads are dropped; other ports are not inspected. */
    h_build_udp(client, 40000, server, GAME_PORT, "", 0);
    CHECK_EQ(h_run(), CF_EBPF_DROP);
    h_build_udp(client, 40000, server, 53, "", 0);
    CHECK_EQ(h_run(), CF_EBPF_PASS);

    /* Fail open when the flow state table is not enabled. */
    harness_reset();
    h_flow_state_enabled = 0;
    CHECK_EQ(send_msg(40000, 2), CF_EBPF_PASS);

    return harness_finish("flow_handshake");
}
