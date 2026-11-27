// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/*
 * Native test harness for the example programs.
 *
 * A test file includes an example's C source and then this header. The
 * example's helper declarations come from the real `cf_ebpf_helper.h`, so the
 * mocks below are type-checked against the same function pointer types that
 * programs use on Cloudflare's network. `harness_reset()` points every helper
 * at an in-memory mock.
 *
 * The mocks model the documented helper contracts. They are a convenience for
 * exercising program logic, not a replacement for `pfp-verifier` or for the
 * PCAP debug endpoint.
 *
 * Do not include <stdlib.h> or <string.h>: they declare `rand` and `memcmp`,
 * which the PFP headers also define.
 */

#ifndef PFP_EXAMPLES_HARNESS_H
#define PFP_EXAMPLES_HARNESS_H

/* Not every test uses every helper. */
#pragma GCC diagnostic ignored "-Wunused-function"

#include <stdio.h>

/* --- assertions ---------------------------------------------------------- */

static int harness_failures = 0;
static int harness_checks = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        harness_checks++;                                                    \
        if (!(cond)) {                                                       \
            harness_failures++;                                              \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, \
                    #cond);                                                  \
        }                                                                    \
    } while (0)

#define CHECK_EQ(actual, expected)                                           \
    do {                                                                     \
        harness_checks++;                                                    \
        unsigned long long _a = (unsigned long long)(actual);                \
        unsigned long long _e = (unsigned long long)(expected);              \
        if (_a != _e) {                                                      \
            harness_failures++;                                              \
            fprintf(stderr, "%s:%d: %s == %llu, expected %llu\n", __FILE__,  \
                    __LINE__, #actual, _a, _e);                              \
        }                                                                    \
    } while (0)

static int harness_finish(const char *name) {
    if (harness_failures) {
        fprintf(stderr, "%s: %d of %d checks failed\n", name, harness_failures,
                harness_checks);
        return 1;
    }
    printf("%s: all %d checks passed\n", name, harness_checks);
    return 0;
}

/* --- byte helpers -------------------------------------------------------- */

static void h_memset(void *dst, int c, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    for (size_t i = 0; i < n; i++) d[i] = (uint8_t)c;
}

static void h_memcpy(void *dst, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
}

static int h_memeq(const void *a, const void *b, size_t n) {
    const uint8_t *x = (const uint8_t *)a;
    const uint8_t *y = (const uint8_t *)b;
    for (size_t i = 0; i < n; i++)
        if (x[i] != y[i]) return 0;
    return 1;
}

/* --- current packet ------------------------------------------------------ */

struct h_addr {
    uint8_t family; /* 4 or 6 */
    uint8_t bytes[16];
};

static struct cf_ebpf_packet_data h_packet;
static struct cf_ebpf_generic_ctx h_ctx;
static struct h_addr h_src, h_dst;
static uint16_t h_sport, h_dport;

static struct h_addr h_ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    struct h_addr x;
    h_memset(&x, 0, sizeof(x));
    x.family = 4;
    x.bytes[0] = a; x.bytes[1] = b; x.bytes[2] = c; x.bytes[3] = d;
    return x;
}

/* 2001:db8::<last> */
static struct h_addr h_ipv6_doc(uint8_t last) {
    struct h_addr x;
    h_memset(&x, 0, sizeof(x));
    x.family = 6;
    x.bytes[0] = 0x20; x.bytes[1] = 0x01; x.bytes[2] = 0x0d; x.bytes[3] = 0xb8;
    x.bytes[15] = last;
    return x;
}

/* Builds an IPv4 or IPv6 UDP packet in the context passed to cf_ebpf_main. */
static void h_build_udp(struct h_addr src, uint16_t sport, struct h_addr dst,
                        uint16_t dport, const void *payload, size_t len) {
    h_memset(&h_packet, 0, sizeof(h_packet));
    uint8_t *b = h_packet.packet_buffer;
    size_t ip_len;
    if (src.family == 4) {
        struct iphdr *ip = (struct iphdr *)b;
        ip->version = 4;
        ip->ihl = 5;
        ip->tot_len = htons((uint16_t)(20 + 8 + len));
        ip->ttl = 64;
        ip->protocol = 17;
        h_memcpy(&ip->saddr, src.bytes, 4);
        h_memcpy(&ip->daddr, dst.bytes, 4);
        ip_len = 20;
    } else {
        struct ipv6hdr *ip6 = (struct ipv6hdr *)b;
        ip6->version = 6;
        ip6->payload_len = htons((uint16_t)(8 + len));
        ip6->nexthdr = 17;
        ip6->hop_limit = 64;
        h_memcpy(ip6->saddr, src.bytes, 16);
        h_memcpy(ip6->daddr, dst.bytes, 16);
        ip_len = 40;
    }
    struct udphdr *udp = (struct udphdr *)(b + ip_len);
    udp->source = htons(sport);
    udp->dest = htons(dport);
    udp->len = htons((uint16_t)(8 + len));
    h_memcpy(b + ip_len + 8, payload, len);

    h_packet.ip_header_length = ip_len;
    h_packet.total_packet_length = ip_len + 8 + len;
    h_ctx.data = (uint64_t)(uintptr_t)&h_packet;
    h_ctx.data_end = (uint64_t)(uintptr_t)(&h_packet + 1);
    h_ctx.metadata = 0;

    h_src = src;
    h_dst = dst;
    h_sport = sport;
    h_dport = dport;
}

/* --- clock and random numbers -------------------------------------------- */

static int64_t h_now = 1767225600; /* 2026-01-01T00:00:00Z */
static uint64_t h_rand_value = 0x1122334455667788ULL;

static uint64_t mock_rand(void) { return h_rand_value; }
static int64_t mock_timestamp(void) { return h_now; }

/* --- source IP state table ----------------------------------------------- */

#define H_TABLE_SIZE 64

struct h_src_entry {
    int used;
    struct h_addr addr;
    uint8_t status;
    uint64_t expiry; /* absolute UNIX timestamp; 0 means no expiry */
    uint64_t data;
    int64_t last_challenge; /* 0 if never challenged */
};

static struct h_src_entry h_src_table[H_TABLE_SIZE];
/*
 * The status helpers are available with either the source IP state or the
 * challenges feature. The data helpers require the source IP state feature.
 */
static int h_src_state_enabled = 1;
static int h_src_status_enabled = 1;

static struct h_src_entry *h_src_find(const struct h_addr *a, int create) {
    for (int i = 0; i < H_TABLE_SIZE; i++)
        if (h_src_table[i].used && h_memeq(&h_src_table[i].addr, a, sizeof(*a)))
            return &h_src_table[i];
    if (!create) return NULL;
    for (int i = 0; i < H_TABLE_SIZE; i++)
        if (!h_src_table[i].used) {
            h_memset(&h_src_table[i], 0, sizeof(h_src_table[i]));
            h_src_table[i].used = 1;
            h_src_table[i].addr = *a;
            return &h_src_table[i];
        }
    return NULL;
}

static int mock_get_src_ip_status(uint8_t *status, size_t status_len,
                                  uint64_t *expiry, size_t expiry_len) {
    if (!h_src_status_enabled) return -5;
    if ((status && status_len < 1) || (expiry && expiry_len < 8)) return -3;
    if (!status && !expiry) return -4;
    struct h_src_entry *e = h_src_find(&h_src, 0);
    if (!e) return -1;
    /* An expired status reads back as NONE with no expiry. */
    if (e->expiry && (uint64_t)h_now > e->expiry) {
        e->status = CF_EBPF_SRC_IP_STATUS_NONE;
        e->expiry = 0;
    }
    if (status) *status = e->status;
    if (expiry) *expiry = e->expiry;
    return 0;
}

static int mock_set_src_ip_status(uint8_t status, uint64_t expiry_secs) {
    if (!h_src_status_enabled) return -5;
    struct h_src_entry *e = h_src_find(&h_src, 1);
    if (!e) return -2;
    /* Unknown values are stored as NONE; NONE clears the expiry. */
    if (status > CF_EBPF_SRC_IP_STATUS_BLOCKLISTED)
        status = CF_EBPF_SRC_IP_STATUS_NONE;
    e->status = status;
    e->expiry = (status != CF_EBPF_SRC_IP_STATUS_NONE && expiry_secs)
                    ? (uint64_t)h_now + expiry_secs
                    : 0;
    return 0;
}

static int mock_get_src_ip_data(uint64_t *data, size_t data_len) {
    if (!h_src_state_enabled) return -5;
    if (!data) return -4;
    if (data_len < 8) return -3;
    struct h_src_entry *e = h_src_find(&h_src, 0);
    if (!e) return -1;
    *data = e->data;
    return 0;
}

static int mock_set_src_ip_data(uint64_t data) {
    if (!h_src_state_enabled) return -5;
    struct h_src_entry *e = h_src_find(&h_src, 1);
    if (!e) return -2;
    e->data = data;
    return 0;
}

/* Test accessor: returns the entry for an address, or NULL. */
static struct h_src_entry *h_src_entry_for(struct h_addr a) {
    return h_src_find(&a, 0);
}

/* --- flow state table ---------------------------------------------------- */

struct h_flow_entry {
    int used;
    struct h_addr src, dst;
    uint16_t sport, dport;
    uint64_t data;
};

static struct h_flow_entry h_flow_table[H_TABLE_SIZE];
static int h_flow_state_enabled = 1;

static struct h_flow_entry *h_flow_find(int create) {
    for (int i = 0; i < H_TABLE_SIZE; i++) {
        struct h_flow_entry *f = &h_flow_table[i];
        if (f->used && f->sport == h_sport && f->dport == h_dport &&
            h_memeq(&f->src, &h_src, sizeof(h_src)) &&
            h_memeq(&f->dst, &h_dst, sizeof(h_dst)))
            return f;
    }
    if (!create) return NULL;
    for (int i = 0; i < H_TABLE_SIZE; i++)
        if (!h_flow_table[i].used) {
            struct h_flow_entry *f = &h_flow_table[i];
            h_memset(f, 0, sizeof(*f));
            f->used = 1;
            f->src = h_src;
            f->dst = h_dst;
            f->sport = h_sport;
            f->dport = h_dport;
            return f;
        }
    return NULL;
}

static int mock_get_flow_data(uint64_t *data, size_t data_len) {
    if (!h_flow_state_enabled) return -5;
    if (!data) return -4;
    if (data_len < 8) return -3;
    struct h_flow_entry *f = h_flow_find(0);
    if (!f) return -1;
    *data = f->data;
    return 0;
}

static int mock_set_flow_data(uint64_t data) {
    if (!h_flow_state_enabled) return -5;
    struct h_flow_entry *f = h_flow_find(1);
    if (!f) return -2;
    f->data = data;
    return 0;
}

/* --- challenges ---------------------------------------------------------- */

static uint8_t h_challenge[1500];
static size_t h_challenge_len = 0;
static int h_challenge_calls = 0;
static int h_challenge_ret = 0;      /* force a return code, for example -5 */
static int64_t h_challenge_interval = 2; /* seconds between challenges per IP */
static size_t h_challenge_max = 256;  /* smallest maximum on the network */

/*
 * Models the documented behavior: a successful call records the buffer and
 * creates a source IP entry if none exists. A second challenge to the same
 * source IP within the interval returns -6. The buffer is only sent if the
 * program returns CF_EBPF_DROP in an enabled rule; tests check that.
 */
static int mock_set_challenge(uint8_t *src, size_t src_len) {
    h_challenge_calls++;
    if (h_challenge_ret) return h_challenge_ret;
    if (src_len == 0) {
        h_challenge_len = 0;
        return 0;
    }
    if (src == NULL || src_len > h_challenge_max) return -4;
    struct h_src_entry *e = h_src_find(&h_src, 0);
    if (e && e->last_challenge && h_now < e->last_challenge + h_challenge_interval)
        return -6;
    if (!e) e = h_src_find(&h_src, 1);
    e->last_challenge = h_now;
    h_memcpy(h_challenge, src, src_len);
    h_challenge_len = src_len;
    return 0;
}

/* --- Network Analytics tag ----------------------------------------------- */

static uint64_t h_tag = 0;
static int mock_set_network_analytics_tag(uint64_t value) {
    h_tag = value;
    return 0;
}

/* --- parameter maps ------------------------------------------------------ */

#define H_MAX_PARAMS 4
#define H_MAX_PARAM_ENTRIES 16

struct h_param_entry {
    uint8_t key[16];
    uint64_t value;
};

struct h_param_map {
    int used;
    size_t key_len;   /* 4 or 16 */
    size_t value_len; /* 1, 2, 4, or 8 */
    int count;
    struct h_param_entry entries[H_MAX_PARAM_ENTRIES];
};

static struct h_param_map h_params[H_MAX_PARAMS];
static int h_params_enabled = 1;

static void h_param_define(uint32_t id, size_t key_len, size_t value_len) {
    h_params[id].used = 1;
    h_params[id].key_len = key_len;
    h_params[id].value_len = value_len;
    h_params[id].count = 0;
}

static void h_param_set(uint32_t id, struct h_addr addr, uint64_t value) {
    struct h_param_map *m = &h_params[id];
    struct h_param_entry *e = &m->entries[m->count++];
    h_memset(e, 0, sizeof(*e));
    h_memcpy(e->key, addr.bytes, m->key_len);
    e->value = value;
}

static int mock_param_lookup(uint32_t param_id, const void *key, size_t key_len,
                             void *value, size_t value_len) {
    uint8_t k[16];
    if (key_len <= sizeof(k)) h_memcpy(k, key, key_len);
    h_memset(value, 0, value_len);
    if (!h_params_enabled) return -5;
    if (param_id >= H_MAX_PARAMS || !h_params[param_id].used) return -7;
    struct h_param_map *m = &h_params[param_id];
    if ((key_len != 4 && key_len != 16) || key_len != m->key_len) return -4;
    if (value_len < m->value_len) return -3;
    for (int i = 0; i < m->count; i++)
        if (h_memeq(m->entries[i].key, k, key_len)) {
            /* Native host byte order, as on Cloudflare's network. */
            h_memcpy(value, &m->entries[i].value, m->value_len);
            return (int)m->value_len;
        }
    return -1;
}

/* --- unused helpers ------------------------------------------------------ */

static int mock_unsupported_hash(uint8_t *src, size_t src_len, uint8_t *dest,
                                 size_t dest_len) {
    (void)src; (void)src_len; (void)dest; (void)dest_len;
    fprintf(stderr, "harness: hash/hmac helpers are not mocked\n");
    harness_failures++;
    return -1;
}

static int64_t mock_entropy(uint8_t *src, size_t src_len) {
    (void)src; (void)src_len;
    fprintf(stderr, "harness: entropy is not mocked\n");
    harness_failures++;
    return -1;
}

/* --- setup --------------------------------------------------------------- */

static void harness_reset(void) {
    h_memset(h_src_table, 0, sizeof(h_src_table));
    h_memset(h_flow_table, 0, sizeof(h_flow_table));
    h_memset(h_params, 0, sizeof(h_params));
    h_src_state_enabled = h_src_status_enabled = 1;
    h_flow_state_enabled = h_params_enabled = 1;
    h_challenge_len = 0;
    h_challenge_calls = 0;
    h_challenge_ret = 0;
    h_challenge_interval = 2;
    h_challenge_max = 256;
    h_tag = 0;
    h_now = 1767225600;

    rand = mock_rand;
    timestamp = mock_timestamp;
    hash_md5 = hash_sha256 = hash_sha512 = mock_unsupported_hash;
    hmac_sha256 = hmac_sha512 = mock_unsupported_hash;
    _cf_ebpf_hash_crc32_raw = mock_unsupported_hash;
    set_challenge = mock_set_challenge;
    _cf_ebpf_get_src_ip_status_raw = mock_get_src_ip_status;
    set_src_ip_status = mock_set_src_ip_status;
    _cf_ebpf_get_src_ip_data_raw = mock_get_src_ip_data;
    set_src_ip_data = mock_set_src_ip_data;
    _cf_ebpf_get_flow_data_raw = mock_get_flow_data;
    set_flow_data = mock_set_flow_data;
    entropy = mock_entropy;
    set_network_analytics_tag = mock_set_network_analytics_tag;
    param_lookup = mock_param_lookup;
}

/* Runs the program against the packet built by h_build_udp(). */
static uint64_t h_run(void) { return cf_ebpf_main(&h_ctx); }

#endif
