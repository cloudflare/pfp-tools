// Copyright (c) 2024 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

#ifndef CF_EBPF_HELPER_H
#define CF_EBPF_HELPER_H

#include <stdint.h>

enum cf_ebpf_helper_type
{
    /* Reserved and unused. */
    CF_EBPF_UNUSED = 0,

    /* Get a random number. */
    CF_EBPF_RAND_V0 = 1,

    /* Get the number of non-leap seconds since January 1, 1970 0:00:00 UTC (aka “UNIX timestamp”). */
    CF_EBPF_TIMESTAMP_V0 = 2,

    /* (debugging mode only) print a message to the stdout. This is a noop outside of debug mode. */
    CF_EBPF_PRINTF_V0 = 3,

    /* calculates the md5 hash of a buffer */
    CF_EBPF_HASH_MD5_V0 = 4,

    /* calculate the sha256 hash of a buffer */
    CF_EBPF_HASH_SHA256_V0 = 5,

    /* calculate the sha512 hash of a buffer */
    CF_EBPF_HASH_SHA512_V0 = 6,

    /* caclulate the CRC32 (ISO 3309 variant) hash of a buffer */
    CF_EBPF_HASH_CRC32_ISO_HDLC_V0 = 7,

    /* sha256 hmac using secret key stored by engine */
    CF_EBPF_HMAC_SHA256_V0 = 8,

    /* sha512 hmac using secret key stored by engine */
    CF_EBPF_HMAC_SHA512_V0 = 9,

    /* sets the per-packet challenge buffer. passing src_len=0 clears the buffer. */
    CF_EBPF_SET_CHALLENGE_V0 = 10,

    /* get the status and expiry for a source IP */
    CF_EBPF_GET_SRC_IP_STATUS_V0 = 11,

    /* set the status and expiry for a source IP */
    CF_EBPF_SET_SRC_IP_STATUS_V0 = 12,

    /* get the user-defined data for a source IP */
    CF_EBPF_GET_SRC_IP_DATA_V0 = 13,

    /* set the user-defined data for a source IP */
    CF_EBPF_SET_SRC_IP_DATA_V0 = 14,

    /* get the user-defined data for a flow (4-tuple) */
    CF_EBPF_GET_FLOW_DATA_V0 = 15,

    /* set the user-defined data for a flow (4-tuple) */
    CF_EBPF_SET_FLOW_DATA_V0 = 16,

    /* calculate the Shannon entropy of a buffer, returned as millibits (0-8000) */
    CF_EBPF_ENTROPY_V0 = 17,

    /* set a custom value for network analytics */
    CF_EBPF_SET_NETWORK_ANALYTICS_TAG_V0 = 18,
    
    CF_EBPF_HASH_BLAKE2B_512_V0 = 19,
    
    CF_EBPF_HMAC_BLAKE2B_512_V0 = 20,

    CF_EBPF_NUM_HELPERS_MAX,
};

#ifdef CF_EBPF_HELPER_V0
static uint64_t (*rand)     (void) = (uint64_t (*)(void)) CF_EBPF_RAND_V0;
static int64_t  (*timestamp)(void) = (int64_t  (*)(void)) CF_EBPF_TIMESTAMP_V0;

static uint64_t (*_cf_ebpf_printf_raw)(const char *fmt, uint64_t v1, uint64_t v2, uint64_t v3) =
    (uint64_t (*)(const char *, uint64_t, uint64_t, uint64_t))CF_EBPF_PRINTF_V0;
#define BPF_PRINTF_0(fmt)           _cf_ebpf_printf_raw(fmt, 0, 0, 0)
#define BPF_PRINTF_1(fmt, a)        _cf_ebpf_printf_raw(fmt, (uint64_t)(a), 0, 0)
#define BPF_PRINTF_2(fmt, a, b)     _cf_ebpf_printf_raw(fmt, (uint64_t)(a), (uint64_t)(b), 0)
#define BPF_PRINTF_3(fmt, a, b, c)  _cf_ebpf_printf_raw(fmt, (uint64_t)(a), (uint64_t)(b), (uint64_t)(c))
#define _GET_OVERRIDE(_1, _2, _3, _4, NAME, ...) NAME
#define cf_ebpf_printf(...) _GET_OVERRIDE(__VA_ARGS__, BPF_PRINTF_3, BPF_PRINTF_2, BPF_PRINTF_1, BPF_PRINTF_0)(__VA_ARGS__)

static int (*hash_md5)    (uint8_t *src, size_t src_len, uint8_t *dest, size_t dest_len) = (int (*)(uint8_t*, size_t, uint8_t*, size_t)) CF_EBPF_HASH_MD5_V0;
static int (*hash_sha256) (uint8_t *src, size_t src_len, uint8_t *dest, size_t dest_len) = (int (*)(uint8_t*, size_t, uint8_t*, size_t)) CF_EBPF_HASH_SHA256_V0;
static int (*hash_sha512) (uint8_t *src, size_t src_len, uint8_t *dest, size_t dest_len) = (int (*)(uint8_t*, size_t, uint8_t*, size_t)) CF_EBPF_HASH_SHA512_V0;

static int (*_cf_ebpf_hash_crc32_raw)  (uint8_t *src, size_t src_len, uint8_t *dest, size_t dest_len) = (int (*)(uint8_t*, size_t, uint8_t*, size_t)) CF_EBPF_HASH_CRC32_ISO_HDLC_V0;

static inline int hash_crc32(uint8_t *src, size_t src_len, uint64_t *dest) {
    uint8_t buffer[8] = {0};
    int status = _cf_ebpf_hash_crc32_raw(src, src_len, buffer, 8);
    if (status < 0) return status;
    uint64_t result = 0;

    for (int offset = 0; offset < 64; offset += 8)
        result |= (( (uint64_t) (buffer[offset / 8]) ) << offset);

    *dest = result;
    return status;
}

static int (*hmac_sha256) (uint8_t *src, size_t src_len, uint8_t *dest, size_t dest_len) = (int (*)(uint8_t*, size_t, uint8_t*, size_t)) CF_EBPF_HMAC_SHA256_V0;
static int (*hmac_sha512) (uint8_t *src, size_t src_len, uint8_t *dest, size_t dest_len) = (int (*)(uint8_t*, size_t, uint8_t*, size_t)) CF_EBPF_HMAC_SHA512_V0;

static int (*set_challenge) (uint8_t *src, size_t src_len) = (int (*)(uint8_t*, size_t)) CF_EBPF_SET_CHALLENGE_V0;

/* Source IP status values */
#define CF_EBPF_SRC_IP_STATUS_NONE        0
#define CF_EBPF_SRC_IP_STATUS_CHALLENGED  1
#define CF_EBPF_SRC_IP_STATUS_VERIFIED    2
#define CF_EBPF_SRC_IP_STATUS_BLOCKLISTED 3

static int (*_cf_ebpf_get_src_ip_status_raw) (uint8_t *out_status, size_t status_len, uint64_t *out_expiry, size_t expiry_len) = (int (*)(uint8_t*, size_t, uint64_t*, size_t)) CF_EBPF_GET_SRC_IP_STATUS_V0;
#define get_src_ip_status(out_status, out_expiry) \
    _cf_ebpf_get_src_ip_status_raw((out_status), sizeof(uint8_t), (out_expiry), sizeof(uint64_t))

static int (*set_src_ip_status) (uint8_t status, uint64_t expiry_secs) = (int (*)(uint8_t, uint64_t)) CF_EBPF_SET_SRC_IP_STATUS_V0;

static int (*_cf_ebpf_get_src_ip_data_raw) (uint64_t *out_data, size_t data_len) = (int (*)(uint64_t*, size_t)) CF_EBPF_GET_SRC_IP_DATA_V0;
#define get_src_ip_data(out_data) \
    _cf_ebpf_get_src_ip_data_raw((out_data), sizeof(uint64_t))

static int (*set_src_ip_data) (uint64_t data) = (int (*)(uint64_t)) CF_EBPF_SET_SRC_IP_DATA_V0;

static int (*_cf_ebpf_get_flow_data_raw) (uint64_t *out_data, size_t data_len) = (int (*)(uint64_t*, size_t)) CF_EBPF_GET_FLOW_DATA_V0;
#define get_flow_data(out_data) \
    _cf_ebpf_get_flow_data_raw((out_data), sizeof(uint64_t))

static int (*set_flow_data) (uint64_t data) = (int (*)(uint64_t)) CF_EBPF_SET_FLOW_DATA_V0;

static int64_t (*entropy) (uint8_t *src, size_t src_len) = (int64_t (*)(uint8_t*, size_t)) CF_EBPF_ENTROPY_V0;

static int (*set_network_analytics_tag)     (uint64_t value) = (int (*)(uint64_t)) CF_EBPF_SET_NETWORK_ANALYTICS_TAG_V0;

static int (*hash_blake2b512) (const uint8_t *src, size_t src_len, uint8_t *dest, size_t dest_len) = (int (*)(const uint8_t*, size_t, uint8_t*, size_t)) CF_EBPF_HASH_BLAKE2B_512_V0;
static int (*hmac_blake2b512) (const uint8_t *src, size_t src_len, uint8_t *dest, size_t dest_len) = (int (*)(const uint8_t*, size_t, uint8_t*, size_t)) CF_EBPF_HMAC_BLAKE2B_512_V0;

#endif

#endif
