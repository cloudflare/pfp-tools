// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/*
 * Verify source IPs with a challenge-response exchange.
 *
 * The first packet from an unknown source IP is dropped, and Cloudflare sends
 * a challenge containing a random nonce back to that source IP. The client
 * proves that it can receive traffic at its source IP by echoing the nonce.
 * After a correct response, the source IP is verified and its packets pass
 * until the verification expires.
 *
 * Requires the challenges feature and the source IP state table. The client
 * must implement the challenge protocol defined below.
 */

#define CF_EBPF_HELPER_V0

#include <cf_ebpf_defs.h>
#include <cf_ebpf_helper.h>

#define CHALLENGE_MAGIC 0x43484C47 /* "CHLG": sent by Cloudflare */
#define RESPONSE_MAGIC 0x52455350  /* "RESP": sent by the client */

#define CHALLENGE_TIMEOUT_SECONDS 30 /* Time to answer a challenge. */
#define VERIFIED_SECONDS 3600        /* How long a verification lasts. */

/*
 * Challenge and response messages. The client echoes the nonce from the
 * challenge in its response. Multi-byte fields are in network byte order.
 */
struct challenge_msg {
    uint32_t magic;
    uint32_t reserved;
    uint64_t nonce;
} __attribute__((packed));

/* Sends the challenge for `nonce`. Returns the set_challenge() result. */
static inline int send_challenge(uint64_t nonce)
{
    struct challenge_msg msg = {
        .magic = htonl(CHALLENGE_MAGIC),
        .reserved = 0,
        .nonce = htonll(nonce),
    };
    return set_challenge((uint8_t *)&msg, sizeof(msg));
}

uint64_t cf_ebpf_main(void *state)
{
    struct cf_ebpf_generic_ctx *ctx = state;
    struct cf_ebpf_parsed_headers headers;
    struct cf_ebpf_packet_data *p;

    if (parse_packet_data(ctx, &p, &headers) != 0) {
        return CF_EBPF_DROP;
    }

    /*
     * Packets from blocklisted source IPs never reach the program, and
     * expired statuses read back as CF_EBPF_SRC_IP_STATUS_NONE, so there is
     * no need to check either case here.
     */
    uint8_t status = CF_EBPF_SRC_IP_STATUS_NONE;
    uint64_t expiry = 0;
    int ret = get_src_ip_status(&status, &expiry);
    if (ret != 0 && ret != -1) {
        /* The feature is not enabled for the account: fail open. */
        return CF_EBPF_PASS;
    }

    if (ret == 0 && status == CF_EBPF_SRC_IP_STATUS_VERIFIED) {
        return CF_EBPF_PASS;
    }

    if (ret == 0 && status == CF_EBPF_SRC_IP_STATUS_CHALLENGED) {
        uint64_t nonce = 0;
        ret = get_src_ip_data(&nonce);
        if (ret == -5) {
            /* Source IP state is not enabled for the account: fail open. */
            return CF_EBPF_PASS;
        }
        if (ret != 0) {
            return CF_EBPF_DROP;
        }

        struct challenge_msg *resp = (struct challenge_msg *)(headers.udp + 1);
        if ((uint8_t *)(resp + 1) <= headers.data_end &&
            ntohl(resp->magic) == RESPONSE_MAGIC &&
            ntohll(resp->nonce) == nonce) {
            set_src_ip_status(CF_EBPF_SRC_IP_STATUS_VERIFIED, VERIFIED_SECONDS);
            /* The response is not meant for the origin: drop it. */
            return CF_EBPF_DROP;
        }

        /*
         * Not a valid response, for example because the client did not
         * receive the challenge. Send the same nonce again. Do not blocklist
         * the source IP: UDP source IPs can be spoofed, so an attacker could
         * otherwise get a legitimate client blocked. set_challenge() limits
         * how often a source IP is challenged.
         */
        send_challenge(nonce);
        return CF_EBPF_DROP;
    }

    /* Unknown source IP, or a previous status expired: challenge it. */
    uint64_t nonce = 0;
    if (get_src_ip_data(&nonce) == -5) {
        /*
         * Source IP state is not enabled for the account, so the program
         * cannot store the nonce to check the response: fail open.
         */
        return CF_EBPF_PASS;
    }
    nonce = rand();
    ret = send_challenge(nonce);
    if (ret == -5) {
        /* Challenges are not enabled for the account: fail open. */
        return CF_EBPF_PASS;
    }
    if (ret != 0) {
        /* Rate limited: try again on a later packet. */
        return CF_EBPF_DROP;
    }
    if (set_src_ip_data(nonce) != 0) {
        /* The nonce could not be stored: do not send the challenge. */
        return CF_EBPF_PASS;
    }
    set_src_ip_status(CF_EBPF_SRC_IP_STATUS_CHALLENGED, CHALLENGE_TIMEOUT_SECONDS);

    /* The challenge is only sent when the program drops the packet. */
    return CF_EBPF_DROP;
}
