// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/*
 * Require each flow to start with a handshake message.
 *
 * Uses the flow state table, keyed by source IP, source port, destination IP,
 * and destination port, to accept a flow only after it sends a CONNECT
 * message. Flows that stay idle for longer than IDLE_TIMEOUT_SECONDS must send
 * CONNECT again.
 *
 * This enforces protocol conformance. It does not prove that a source IP is
 * genuine, because a spoofed packet can also carry CONNECT. To verify source
 * IPs, use a challenge (see challenge_response.c).
 */

#define CF_EBPF_HELPER_V0

#include <cf_ebpf_defs.h>
#include <cf_ebpf_helper.h>

#define GAME_PORT 27015
#define MSG_CONNECT 1
#define IDLE_TIMEOUT_SECONDS 30

/* First byte of every message. */
struct msg_hdr {
    uint8_t type;
};

uint64_t cf_ebpf_main(void *state)
{
    struct cf_ebpf_generic_ctx *ctx = state;
    struct cf_ebpf_parsed_headers headers;
    struct cf_ebpf_packet_data *p;

    if (parse_packet_data(ctx, &p, &headers) != 0) {
        return CF_EBPF_DROP;
    }

    struct udphdr *udp = headers.udp;
    if (ntohs(udp->dest) != GAME_PORT) {
        return CF_EBPF_PASS;
    }

    struct msg_hdr *msg = (struct msg_hdr *)(udp + 1);
    if ((uint8_t *)(msg + 1) > headers.data_end) {
        return CF_EBPF_DROP;
    }

    int64_t now = timestamp();
    if (now <= 0) {
        return CF_EBPF_PASS;
    }

    /* A CONNECT message opens (or refreshes) the flow. */
    if (msg->type == MSG_CONNECT) {
        set_flow_data((uint64_t)now);
        return CF_EBPF_PASS;
    }

    /* The flow data holds the time the flow was last seen. */
    uint64_t last_seen;
    int ret = get_flow_data(&last_seen);
    if (ret == -1) {
        /* No entry: the flow did not send CONNECT first. */
        return CF_EBPF_DROP;
    }
    if (ret != 0) {
        /* Any other error, for example state not enabled: fail open. */
        return CF_EBPF_PASS;
    }

    if ((uint64_t)now - last_seen > IDLE_TIMEOUT_SECONDS) {
        return CF_EBPF_DROP;
    }

    set_flow_data((uint64_t)now);
    return CF_EBPF_PASS;
}
