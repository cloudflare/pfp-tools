// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/*
 * Apply per-source-IP policies from parameter maps.
 *
 * Reads a policy for the packet's source IP from one of two parameter maps
 * that you manage through the API: map 0 holds IPv4 addresses and map 1 holds
 * IPv6 addresses, both with u8 values. Addresses that are not in a map pass.
 *
 * Example parameters document:
 *
 * {
 *   "params": {
 *     "source_policy_v4": {
 *       "id": 0, "type": "map", "key": "ipv4", "value": "u8",
 *       "entries": { "192.0.2.1": 2 }
 *     },
 *     "source_policy_v6": {
 *       "id": 1, "type": "map", "key": "ipv6", "value": "u8",
 *       "entries": { "2001:db8::1": 2 }
 *     }
 *   }
 * }
 */

#define CF_EBPF_HELPER_V0

#include <cf_ebpf_defs.h>
#include <cf_ebpf_helper.h>

/* Map IDs, as configured in the parameters document. */
#define PARAM_SOURCE_POLICY_V4 0 /* ipv4 keys, u8 values */
#define PARAM_SOURCE_POLICY_V6 1 /* ipv6 keys, u8 values */

/* Policy values stored in the maps. */
#define POLICY_DEFAULT 0
#define POLICY_ALLOW 1
#define POLICY_BLOCK 2

uint64_t cf_ebpf_main(void *state)
{
    struct cf_ebpf_generic_ctx *ctx = state;
    struct cf_ebpf_parsed_headers headers;
    struct cf_ebpf_packet_data *p;

    if (parse_packet_data(ctx, &p, &headers) != 0) {
        return CF_EBPF_DROP;
    }

    /*
     * Copy the source address into one zero-initialized stack buffer that is
     * large enough for either family. The compiler can merge the two lookups
     * into one call, and the verifier must then prove that up to 16 bytes of
     * `key` are readable and initialized on both paths. Keys are in network
     * byte order, exactly as in the IP header.
     */
    uint8_t key[16] = {0};
    uint32_t param_id;
    size_t key_len;

    if (headers.ipv4 != NULL) {
        __builtin_memcpy(key, &headers.ipv4->saddr, 4);
        param_id = PARAM_SOURCE_POLICY_V4;
        key_len = 4;
    } else {
        __builtin_memcpy(key, headers.ipv6->saddr, 16);
        param_id = PARAM_SOURCE_POLICY_V6;
        key_len = 16;
    }

    uint8_t policy = POLICY_DEFAULT;
    int ret = param_lookup(param_id, key, key_len, &policy, sizeof(policy));

    /*
     * On success, param_lookup returns the number of bytes copied. Any
     * negative value means no policy applies: the address is not in the map
     * (-1), or the maps are missing or do not match the types this program
     * expects (-3, -4, -5, -7). Fail open so that a configuration mistake
     * does not drop legitimate traffic.
     */
    if (ret != sizeof(policy)) {
        return CF_EBPF_PASS;
    }

    /* Values are in host byte order. No conversion is needed. */
    if (policy == POLICY_BLOCK) {
        return CF_EBPF_DROP;
    }

    /* POLICY_ALLOW and POLICY_DEFAULT: apply the rest of your logic here. */
    return CF_EBPF_PASS;
}
