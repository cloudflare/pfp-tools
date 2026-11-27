// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/*
 * Validate a custom application header.
 *
 * Drops UDP packets that do not carry a well-formed header for a fictional
 * game protocol, and tags each drop with a reason that you can filter on in
 * Network Analytics.
 */

#define CF_EBPF_HELPER_V0

#include <cf_ebpf_defs.h>
#include <cf_ebpf_helper.h>

#define GAME_PORT 27015
#define GAME_MAGIC 0x47414D45 /* "GAME" */
#define GAME_VERSION 1
#define GAME_TYPE_MAX 4

/* Drop reasons reported with set_network_analytics_tag(). */
#define TAG_TOO_SHORT 1
#define TAG_BAD_MAGIC 2
#define TAG_BAD_VERSION 3
#define TAG_BAD_TYPE 4
#define TAG_BAD_LENGTH 5

/* Application header. Multi-byte fields are in network byte order. */
struct game_hdr {
    uint32_t magic;
    uint8_t version;
    uint8_t type;
    uint16_t length; /* Number of payload bytes after this header. */
} __attribute__((packed));

uint64_t cf_ebpf_main(void *state)
{
    struct cf_ebpf_generic_ctx *ctx = state;
    struct cf_ebpf_parsed_headers headers;
    struct cf_ebpf_packet_data *p;

    if (parse_packet_data(ctx, &p, &headers) != 0) {
        return CF_EBPF_DROP;
    }

    struct udphdr *udp = headers.udp;

    /* Only inspect traffic for the game server port. */
    if (ntohs(udp->dest) != GAME_PORT) {
        return CF_EBPF_PASS;
    }

    /* Check that the full header is inside the packet before reading it. */
    struct game_hdr *hdr = (struct game_hdr *)(udp + 1);
    if ((uint8_t *)(hdr + 1) > headers.data_end) {
        set_network_analytics_tag(TAG_TOO_SHORT);
        return CF_EBPF_DROP;
    }

    if (ntohl(hdr->magic) != GAME_MAGIC) {
        set_network_analytics_tag(TAG_BAD_MAGIC);
        return CF_EBPF_DROP;
    }

    if (hdr->version != GAME_VERSION) {
        set_network_analytics_tag(TAG_BAD_VERSION);
        return CF_EBPF_DROP;
    }

    if (hdr->type == 0 || hdr->type > GAME_TYPE_MAX) {
        set_network_analytics_tag(TAG_BAD_TYPE);
        return CF_EBPF_DROP;
    }

    /*
     * The declared payload length must match the bytes actually received.
     * Compare lengths as integers: the verifier rejects comparisons between
     * packet pointers that have a variable offset.
     */
    size_t udp_payload_len = p->total_packet_length - p->ip_header_length -
                             sizeof(struct udphdr);
    if (udp_payload_len != sizeof(struct game_hdr) + ntohs(hdr->length)) {
        set_network_analytics_tag(TAG_BAD_LENGTH);
        return CF_EBPF_DROP;
    }

    return CF_EBPF_PASS;
}
