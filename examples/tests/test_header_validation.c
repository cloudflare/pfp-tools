// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

#include "../header_validation.c"
#include "harness.h"

static struct h_addr client, server;

static uint64_t send_game(const struct game_hdr *hdr, size_t payload_len) {
    uint8_t buf[256];
    h_memset(buf, 0xAB, sizeof(buf));
    h_memcpy(buf, hdr, sizeof(*hdr));
    h_tag = 0;
    h_build_udp(client, 50000, server, GAME_PORT, buf, sizeof(*hdr) + payload_len);
    return h_run();
}

static struct game_hdr valid_hdr(uint16_t payload_len) {
    struct game_hdr h;
    h.magic = htonl(GAME_MAGIC);
    h.version = GAME_VERSION;
    h.type = 1;
    h.length = htons(payload_len);
    return h;
}

int main(void) {
    harness_reset();
    client = h_ipv4(198, 51, 100, 7);
    server = h_ipv4(192, 0, 2, 10);

    /* A well-formed packet passes, with and without payload. */
    struct game_hdr h = valid_hdr(10);
    CHECK_EQ(send_game(&h, 10), CF_EBPF_PASS);
    CHECK_EQ(h_tag, 0);
    h = valid_hdr(0);
    CHECK_EQ(send_game(&h, 0), CF_EBPF_PASS);

    /* IPv6 works the same way. */
    client = h_ipv6_doc(7);
    server = h_ipv6_doc(10);
    h = valid_hdr(10);
    CHECK_EQ(send_game(&h, 10), CF_EBPF_PASS);
    client = h_ipv4(198, 51, 100, 7);
    server = h_ipv4(192, 0, 2, 10);

    /* Traffic to other ports is not inspected. */
    h_build_udp(client, 50000, server, 53, "x", 1);
    CHECK_EQ(h_run(), CF_EBPF_PASS);

    /* Truncated header. */
    h_tag = 0;
    h_build_udp(client, 50000, server, GAME_PORT, "GAM", 3);
    CHECK_EQ(h_run(), CF_EBPF_DROP);
    CHECK_EQ(h_tag, TAG_TOO_SHORT);

    /* Wrong magic. */
    h = valid_hdr(4);
    h.magic = htonl(0xDEADBEEF);
    CHECK_EQ(send_game(&h, 4), CF_EBPF_DROP);
    CHECK_EQ(h_tag, TAG_BAD_MAGIC);

    /* Magic in host byte order instead of network byte order. */
    h = valid_hdr(4);
    h.magic = GAME_MAGIC;
    CHECK_EQ(send_game(&h, 4), CF_EBPF_DROP);
    CHECK_EQ(h_tag, TAG_BAD_MAGIC);

    /* Unsupported version. */
    h = valid_hdr(4);
    h.version = 2;
    CHECK_EQ(send_game(&h, 4), CF_EBPF_DROP);
    CHECK_EQ(h_tag, TAG_BAD_VERSION);

    /* Invalid message types. */
    h = valid_hdr(4);
    h.type = 0;
    CHECK_EQ(send_game(&h, 4), CF_EBPF_DROP);
    CHECK_EQ(h_tag, TAG_BAD_TYPE);
    h.type = GAME_TYPE_MAX + 1;
    CHECK_EQ(send_game(&h, 4), CF_EBPF_DROP);
    CHECK_EQ(h_tag, TAG_BAD_TYPE);
    h.type = GAME_TYPE_MAX;
    CHECK_EQ(send_game(&h, 4), CF_EBPF_PASS);

    /* Declared length longer and shorter than the payload. */
    h = valid_hdr(20);
    CHECK_EQ(send_game(&h, 10), CF_EBPF_DROP);
    CHECK_EQ(h_tag, TAG_BAD_LENGTH);
    h = valid_hdr(5);
    CHECK_EQ(send_game(&h, 10), CF_EBPF_DROP);
    CHECK_EQ(h_tag, TAG_BAD_LENGTH);

    /* A malformed context is dropped. */
    h_build_udp(client, 50000, server, GAME_PORT, "x", 1);
    h_packet.total_packet_length = sizeof(h_packet.packet_buffer) + 1;
    CHECK_EQ(h_run(), CF_EBPF_DROP);

    return harness_finish("header_validation");
}
