// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

#include "../challenge_response.c"
#include "harness.h"

static struct h_addr client, server;

static uint64_t send_data(void) {
    h_build_udp(client, 40000, server, 27015, "hello world", 11);
    return h_run();
}

static uint64_t send_response(uint32_t magic, uint64_t nonce) {
    struct challenge_msg r;
    r.magic = htonl(magic);
    r.reserved = 0;
    r.nonce = htonll(nonce);
    h_build_udp(client, 40000, server, 27015, &r, sizeof(r));
    return h_run();
}

/* Returns the nonce in the last challenge, after checking its format. */
static uint64_t last_challenge_nonce(void) {
    struct challenge_msg c;
    CHECK_EQ(h_challenge_len, sizeof(c));
    h_memcpy(&c, h_challenge, sizeof(c));
    CHECK_EQ(ntohl(c.magic), CHALLENGE_MAGIC);
    return ntohll(c.nonce);
}

static uint8_t status_of(struct h_addr a) {
    uint8_t s = 0;
    uint64_t e = 0;
    struct h_addr saved = h_src;
    h_src = a;
    mock_get_src_ip_status(&s, 1, &e, 8);
    h_src = saved;
    return s;
}

int main(void) {
    harness_reset();
    client = h_ipv4(198, 51, 100, 1);
    server = h_ipv4(192, 0, 2, 10);

    /* An unknown source IP is challenged and its packet is dropped. */
    h_rand_value = 0x0102030405060708ULL;
    CHECK_EQ(send_data(), CF_EBPF_DROP);
    CHECK_EQ(h_challenge_calls, 1);
    CHECK_EQ(last_challenge_nonce(), 0x0102030405060708ULL);
    CHECK_EQ(status_of(client), CF_EBPF_SRC_IP_STATUS_CHALLENGED);
    CHECK_EQ(h_src_entry_for(client)->data, 0x0102030405060708ULL);
    CHECK_EQ(h_src_entry_for(client)->expiry, h_now + CHALLENGE_TIMEOUT_SECONDS);

    /* A wrong nonce is dropped, does not blocklist, and does not rotate the nonce. */
    h_now += 3;
    h_challenge_len = 0;
    CHECK_EQ(send_response(RESPONSE_MAGIC, 0xBAD), CF_EBPF_DROP);
    CHECK_EQ(status_of(client), CF_EBPF_SRC_IP_STATUS_CHALLENGED);
    CHECK_EQ(last_challenge_nonce(), 0x0102030405060708ULL); /* re-sent */

    /* Within the interval, the re-send is rate limited but the packet still drops. */
    h_challenge_len = 0;
    CHECK_EQ(send_data(), CF_EBPF_DROP);
    CHECK_EQ(h_challenge_len, 0);

    /* The right nonce with the wrong magic is not accepted. */
    CHECK_EQ(send_response(CHALLENGE_MAGIC, 0x0102030405060708ULL), CF_EBPF_DROP);
    CHECK_EQ(status_of(client), CF_EBPF_SRC_IP_STATUS_CHALLENGED);

    /* The correct response verifies the source IP and is not forwarded. */
    CHECK_EQ(send_response(RESPONSE_MAGIC, 0x0102030405060708ULL), CF_EBPF_DROP);
    CHECK_EQ(status_of(client), CF_EBPF_SRC_IP_STATUS_VERIFIED);

    /* Verified traffic passes until the verification expires. */
    CHECK_EQ(send_data(), CF_EBPF_PASS);
    h_now += VERIFIED_SECONDS;
    CHECK_EQ(send_data(), CF_EBPF_PASS);
    h_now += 1;
    h_rand_value = 0xAAAA;
    CHECK_EQ(send_data(), CF_EBPF_DROP); /* expired: challenged again */
    CHECK_EQ(last_challenge_nonce(), 0xAAAA);
    CHECK_EQ(status_of(client), CF_EBPF_SRC_IP_STATUS_CHALLENGED);

    /* An unanswered challenge expires, and the next packet gets a new nonce. */
    h_now += CHALLENGE_TIMEOUT_SECONDS + 1;
    h_rand_value = 0xBBBB;
    CHECK_EQ(send_data(), CF_EBPF_DROP);
    CHECK_EQ(last_challenge_nonce(), 0xBBBB);
    CHECK_EQ(send_response(RESPONSE_MAGIC, 0xAAAA), CF_EBPF_DROP); /* old nonce */
    CHECK_EQ(status_of(client), CF_EBPF_SRC_IP_STATUS_CHALLENGED);
    CHECK_EQ(send_response(RESPONSE_MAGIC, 0xBBBB), CF_EBPF_DROP);
    CHECK_EQ(status_of(client), CF_EBPF_SRC_IP_STATUS_VERIFIED);

    /* A source IP is unaffected by another one's state. */
    struct h_addr other = h_ipv6_doc(5);
    struct h_addr saved = client;
    client = other;
    server = h_ipv6_doc(10);
    CHECK_EQ(send_data(), CF_EBPF_DROP);
    CHECK_EQ(status_of(other), CF_EBPF_SRC_IP_STATUS_CHALLENGED);
    client = saved;
    server = h_ipv4(192, 0, 2, 10);
    CHECK_EQ(send_data(), CF_EBPF_PASS);

    /* If set_challenge fails (for example -6), no state is recorded. */
    harness_reset();
    h_challenge_ret = -6;
    CHECK_EQ(send_data(), CF_EBPF_DROP);
    CHECK(h_src_entry_for(client) == NULL);

    /* A truncated response is handled as a non-response. */
    harness_reset();
    CHECK_EQ(send_data(), CF_EBPF_DROP);
    h_build_udp(client, 40000, server, 27015, "RESP", 4);
    CHECK_EQ(h_run(), CF_EBPF_DROP);
    CHECK_EQ(status_of(client), CF_EBPF_SRC_IP_STATUS_CHALLENGED);

    /* Fail open when challenges and source IP state are not enabled. */
    harness_reset();
    h_src_status_enabled = 0;
    h_src_state_enabled = 0;
    h_challenge_ret = -5;
    CHECK_EQ(send_data(), CF_EBPF_PASS);

    /* Fail open when only source IP state is enabled. */
    harness_reset();
    h_challenge_ret = -5;
    CHECK_EQ(send_data(), CF_EBPF_PASS);
    CHECK_EQ(send_data(), CF_EBPF_PASS);

    /* Fail open when only challenges are enabled: no challenge is left pending. */
    harness_reset();
    h_src_state_enabled = 0;
    CHECK_EQ(send_data(), CF_EBPF_PASS);
    CHECK(h_src_entry_for(client) == NULL ||
          h_src_entry_for(client)->status != CF_EBPF_SRC_IP_STATUS_CHALLENGED);
    CHECK_EQ(send_data(), CF_EBPF_PASS);

    return harness_finish("challenge_response");
}
