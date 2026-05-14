// Copyright (c) 2024 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

#ifndef CF_EBPF_DEFS_H
#define CF_EBPF_DEFS_H

#include <stdint.h>
#include <stddef.h>

/*
 * Portable network struct definitions.
 * These match the Linux kernel struct layouts and field names so that customer
 * BPF programs compile identically on Linux and macOS.
 */

/* --- byte-order helpers (portable, no system header needed) -------------- */
/* Uses compiler builtins for efficient single-instruction byte swapping. */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  #ifndef htons
    #define htons(x)  ((uint16_t)(x))
  #endif
  #ifndef ntohs
    #define ntohs(x)  ((uint16_t)(x))
  #endif
  #ifndef htonl
    #define htonl(x)  ((uint32_t)(x))
  #endif
  #ifndef ntohl
    #define ntohl(x)  ((uint32_t)(x))
  #endif
  #ifndef htonll
    #define htonll(x) ((uint64_t)(x))
  #endif
  #ifndef ntohll
    #define ntohll(x) ((uint64_t)(x))
  #endif
#else
  #ifndef htons
    #define htons(x) ((uint16_t)__builtin_bswap16((uint16_t)(x)))
  #endif
  #ifndef ntohs
    #define ntohs(x) ((uint16_t)__builtin_bswap16((uint16_t)(x)))
  #endif
  #ifndef htonl
    #define htonl(x) ((uint32_t)__builtin_bswap32((uint32_t)(x)))
  #endif
  #ifndef ntohl
    #define ntohl(x) ((uint32_t)__builtin_bswap32((uint32_t)(x)))
  #endif
  #ifndef htonll
    #define htonll(x) ((uint64_t)__builtin_bswap64((uint64_t)(x)))
  #endif
  #ifndef ntohll
    #define ntohll(x) ((uint64_t)__builtin_bswap64((uint64_t)(x)))
  #endif
#endif

/* --- IPv4 header (RFC 791, 20 bytes without options) --------------------- */
// source: https://github.com/torvalds/linux/blob/a7423e6ea2f8f6f453de79213c26f7a36c86d9a2/include/uapi/linux/ip.h#L87
// this should be identical to the linux definition on the bit level, ignoring compiler attribute stuff that
// linux does.
struct iphdr {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    uint8_t  version:4,
             ihl:4;
#else
    uint8_t  ihl:4,
             version:4;
#endif
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

/* --- IPv6 header (RFC 2460, 40 bytes) ------------------------------------ */
// source: https://github.com/torvalds/linux/blob/a7423e6ea2f8f6f453de79213c26f7a36c86d9a2/include/uapi/linux/ipv6.h#L118
// this should be identical to the linux definition on the bit level, ignoring compiler attribute stuff that
// linux does.
struct ipv6hdr {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    uint8_t  version:4,
             priority:4;
#else
    uint8_t  priority:4,
             version:4;
#endif
    uint8_t  flow_lbl[3];
    uint16_t payload_len;
    uint8_t  nexthdr;
    uint8_t  hop_limit;
    uint8_t  saddr[16];
    uint8_t  daddr[16];
};

/* --- UDP header (RFC 768, 8 bytes) --------------------------------------- */
// source: https://github.com/torvalds/linux/blob/a7423e6ea2f8f6f453de79213c26f7a36c86d9a2/include/uapi/linux/udp.h#L23
// this should be identical to the linux definition on the bit level.
struct udphdr {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};

enum cf_ebpf_return_type
{
    CF_EBPF_PASS = 0,
    CF_EBPF_DROP,
};

struct cf_ebpf_packet_data {
    /* Total length of the packet. */
    size_t   total_packet_length;
    /* Size of the IP header. Supports IPv4 (including options) and IPv6. */
    size_t   ip_header_length;
    /* Bytes of the packet, starting with the IP header. */
    uint8_t  packet_buffer[1500];
};

struct cf_ebpf_parsed_headers {
    /* Pointer to the parsed IPv4 header, if present (otherwise null). */
    struct iphdr   *ipv4;
    /* Pointer to the parsed IPv6 header, if present (otherwise null). */
    struct ipv6hdr *ipv6;
    /* Pointer to the parsed UDP header. */
    struct udphdr  *udp;
    /* Raw pointer to the last valid byte of the packet context data. */
    uint8_t        *data_end;
};

/**
 * @brief Generic context that can be used in any program
 * @param data Pointer to the beginning of any struct
 * @param data_end Pointer to the end of any struct
 * @param metadata Used for the program to store metadata
 */
struct cf_ebpf_generic_ctx
{
    /* Pointer to the beginning of the context data. */
    uint64_t data;
    /* Pointer to the end of the context data. */
    uint64_t data_end;
    /* Space for the program to store metadata. */
    uint64_t metadata;
};

// Function to perform memory checks and return parsed headers.
// Returns 0 on success, 1 on failure (e.g., packet too short, invalid length).
// Output parameters are filled on success.
static inline int parse_packet_data(
    struct cf_ebpf_generic_ctx *ctx,
    struct cf_ebpf_packet_data **out_p,
    struct cf_ebpf_parsed_headers *out_headers
) {
    if (!ctx || !out_headers) {
        return 1;
    }

    struct cf_ebpf_packet_data *p = (struct cf_ebpf_packet_data *)ctx->data;
    struct cf_ebpf_parsed_headers headers = {0};

    // Check that the packet data struct fits in the given memory.
    if (((uint8_t *)(p + 1)) > (uint8_t *)ctx->data_end) {
        return 1;
    }

    // Check that the given total packet length is valid.
    if (p->total_packet_length > sizeof(p->packet_buffer)) {
        return 1;
    }

    uint8_t *data_start = p->packet_buffer;
    uint8_t *data_end = p->packet_buffer + p->total_packet_length;
    headers.data_end = data_end;

    // Check for minimum data size to read the version.
    if (data_start + 1 > data_end) {
        return 1;
    }
    uint8_t version = data_start[0] >> 4;

    // Various checks on the IP header length,
    // and setting the correct header.
    uint32_t ip_header_len = (uint32_t)p->ip_header_length;
    if (ip_header_len > sizeof(p->packet_buffer)) {
        return 1;
    }
    if (data_start + ip_header_len > data_end) {
        return 1;
    }
    if (version == 4) {
        if (data_start + sizeof(struct iphdr) > data_end) {
            return 1;
        }
        if (ip_header_len < sizeof(struct iphdr)) {
            return 1;
        }
	headers.ipv4 = (struct iphdr *)data_start;
    } else if (version == 6) {
        if (data_start + sizeof(struct ipv6hdr) > data_end) {
            return 1;
        }
        if (ip_header_len < sizeof(struct ipv6hdr)) {
            return 1;
        }
	headers.ipv6 = (struct ipv6hdr *)data_start;
    } else {
        // Unknown or unsupported IP version.
        return 1;
    }

    // Check that the UDP header can fit in the packet data.
    struct udphdr *udp_header = (struct udphdr *)(data_start + ip_header_len);
    if ((uint8_t *)(udp_header + 1) > data_end) {
        return 1;
    }
    headers.udp = udp_header;

    if (out_p) {
        *out_p = p;
    }
    *out_headers = headers;

    return 0;
}

/**
 * @brief Compare two memory regions byte-by-byte.
 * @return 0 if equal, -1 if lval < rval, 1 if lval > rval.
 *
 * should be compatible with https://github.com/torvalds/linux/blob/a9aabb3b839aba094ed80861054993785c61462c/lib/string.c#L673
 */
static inline __attribute__((always_inline)) __attribute__((no_builtin))
int memcmp(const void *lval, const void *rval, size_t length) {
    const uint8_t *l = (const uint8_t *)lval;
    const uint8_t *r = (const uint8_t *)rval;
    int res;
    for (size_t i = 0; i < length; i++) {
        if ( (res = (l[i] - r[i])) != 0 ) {
            return (res > 0) - (res < 0);
        }
    }
    return 0;
}

#endif
