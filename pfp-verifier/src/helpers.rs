// Copyright (c) 2024 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

//! Prototypes for helpers that are registered in the platform and passed to the verifier.
//! There's a const-time assertion that the number of helper prototypes here matches the number
//! in [pfp_headers].

use prevail::linux::spec_prototypes::HelperPrototype;
use prevail::spec::ebpf_base::{EbpfArgumentType, EbpfReturnType};

/// Constant assertion that the number of prototypes defined below matches the number in
/// pfp-headers.
const _: () = const {
    assert!(
        HELPER_PROTOS.len() == pfp_headers::cf_ebpf_helper_type_CF_EBPF_NUM_HELPERS_MAX as usize,
        "number of verifier helper prototypes does not match number of helper function headers"
    );
};

/// Base defaults that can be used to copy-construct missing fields of helper prototypes.
const BASE_HELPER_PROTO: HelperPrototype = HelperPrototype {
    name: "",
    return_type: EbpfReturnType::Integer,
    argument_type: [EbpfArgumentType::DontCare; 5],
    reallocate_packet: false,
    ctx_descriptor: None,
    unsupported: false,

    // None of our helpers should be putting the thread to sleep
    might_sleep: false,

    // (venus, 3 June 2026):
    // newer feature from prevail, none of our args to any helper needs to be provably 0
    // afaik.
    zero_args_mask: 0b00000,

    // we don't allow any maps, so this can stay 0, I think.
    allowed_map_types: 0,
};

/// Prototypes for all pfp helper functions.
///
/// ## Important:
/// The order here must exactly match the order in the header files,
/// since the indices here map to the helper type enum in the header.
pub const HELPER_PROTOS: &[HelperPrototype] = &[
    // helper index 0 is unused
    HelperPrototype {
        name: "unused",
        ..BASE_HELPER_PROTO
    },
    // static uint64_t (*rand)     (void) = (uint64_t (*)(void)) CF_EBPF_RAND_V0;
    HelperPrototype {
        name: "rand",
        return_type: EbpfReturnType::Integer,
        ..BASE_HELPER_PROTO
    },
    // static int64_t  (*timestamp)(void) = (int64_t  (*)(void)) CF_EBPF_TIMESTAMP_V0;
    HelperPrototype {
        name: "timestamp",
        return_type: EbpfReturnType::Integer,
        ..BASE_HELPER_PROTO
    },
    /*
    (venus, 2026 Jan 29):
    I made the call to fully exempt the printf helper from the verifier here. We should likely never be exposing
    the real thing to customers, and prevail can't understand what a C string is (you're not allowed to do a buffer
    pointer without immediately following it up with a size arg).

    static uint64_t (*_cf_ebpf_printf_raw)(const char *fmt, uint64_t v1, uint64_t v2, uint64_t v3) =
        (uint64_t (*)(const char *, uint64_t, uint64_t, uint64_t))CF_EBPF_PRINTF_V0;
    */
    HelperPrototype {
        name: "printf",
        ..BASE_HELPER_PROTO
    },
    // static int (*hash_md5)    (uint8_t *src, size_t src_len, uint8_t *dest, size_t dest_len) = (int (*)(uint8_t*, size_t, uint8_t*, size_t)) CF_EBPF_HASH_MD5_V0;
    HelperPrototype {
        name: "hash_md5",
        return_type: EbpfReturnType::Integer,
        argument_type: [
            EbpfArgumentType::PtrToReadableMem,
            EbpfArgumentType::ConstSize,
            EbpfArgumentType::PtrToWritableMem,
            EbpfArgumentType::ConstSize,
            EbpfArgumentType::DontCare,
        ],
        ..BASE_HELPER_PROTO
    },
    // static int (*hash_sha256) (uint8_t *src, size_t src_len, uint8_t *dest, size_t dest_len) = (int (*)(uint8_t*, size_t, uint8_t*, size_t)) CF_EBPF_HASH_SHA256_V0;
    HelperPrototype {
        name: "hash_sha256",
        return_type: EbpfReturnType::Integer,
        argument_type: [
            EbpfArgumentType::PtrToReadableMem,
            EbpfArgumentType::ConstSize,
            EbpfArgumentType::PtrToWritableMem,
            EbpfArgumentType::ConstSize,
            EbpfArgumentType::DontCare,
        ],
        ..BASE_HELPER_PROTO
    },
    // static int (*hash_sha512) (uint8_t *src, size_t src_len, uint8_t *dest, size_t dest_len) = (int (*)(uint8_t*, size_t, uint8_t*, size_t)) CF_EBPF_HASH_SHA512_V0;
    HelperPrototype {
        name: "hash_sha512",
        return_type: EbpfReturnType::Integer,
        argument_type: [
            EbpfArgumentType::PtrToReadableMem,
            EbpfArgumentType::ConstSize,
            EbpfArgumentType::PtrToWritableMem,
            EbpfArgumentType::ConstSize,
            EbpfArgumentType::DontCare,
        ],
        ..BASE_HELPER_PROTO
    },
    // crc32 hashing has a static function that reformats the output of the helper after it returns (thus the different name).
    //
    // static int (*_cf_ebpf_hash_crc32_raw)  (uint8_t *src, size_t src_len, uint8_t *dest, size_t dest_len) = (int (*)(uint8_t*, size_t, uint8_t*, size_t)) CF_EBPF_HASH_CRC32_ISO_HDLC_V0;
    HelperPrototype {
        name: "_cf_ebpf_hash_crc32_raw",
        return_type: EbpfReturnType::Integer,
        argument_type: [
            EbpfArgumentType::PtrToReadableMem,
            EbpfArgumentType::ConstSize,
            EbpfArgumentType::PtrToWritableMem,
            EbpfArgumentType::ConstSize,
            EbpfArgumentType::DontCare,
        ],
        ..BASE_HELPER_PROTO
    },
    // static int (*hmac_sha256) (uint8_t *src, size_t src_len, uint8_t *dest, size_t dest_len) = (int (*)(uint8_t*, size_t, uint8_t*, size_t)) CF_EBPF_HMAC_SHA256_V0;
    HelperPrototype {
        name: "hmac_sha256",
        return_type: EbpfReturnType::Integer,
        argument_type: [
            EbpfArgumentType::PtrToReadableMem,
            EbpfArgumentType::ConstSize,
            EbpfArgumentType::PtrToWritableMem,
            EbpfArgumentType::ConstSize,
            EbpfArgumentType::DontCare,
        ],
        ..BASE_HELPER_PROTO
    },
    // static int (*hmac_sha512) (uint8_t *src, size_t src_len, uint8_t *dest, size_t dest_len) = (int (*)(uint8_t*, size_t, uint8_t*, size_t)) CF_EBPF_HMAC_SHA512_V0;
    HelperPrototype {
        name: "hmac_sha512",
        return_type: EbpfReturnType::Integer,
        argument_type: [
            EbpfArgumentType::PtrToReadableMem,
            EbpfArgumentType::ConstSize,
            EbpfArgumentType::PtrToWritableMem,
            EbpfArgumentType::ConstSize,
            EbpfArgumentType::DontCare,
        ],
        ..BASE_HELPER_PROTO
    },
    // static int (*set_challenge) (uint8_t *src, size_t src_len) = (int (*)(uint8_t*, size_t)) CF_EBPF_SET_CHALLENGE_V0;
    HelperPrototype {
        name: "set_challenge",
        return_type: EbpfReturnType::Integer,
        argument_type: [
            EbpfArgumentType::PtrToReadableMem,
            EbpfArgumentType::ConstSizeOrZero,
            EbpfArgumentType::DontCare,
            EbpfArgumentType::DontCare,
            EbpfArgumentType::DontCare,
        ],
        ..BASE_HELPER_PROTO
    },
    // similar to crc32 hashing, the real version of `get_src_ip*` functions hides behind a macro.

    // static int (*_cf_ebpf_get_src_ip_status_raw) (uint8_t *out_status, size_t status_len, uint64_t *out_expiry, size_t expiry_len) = (int (*)(uint8_t*, size_t, uint64_t*, size_t)) CF_EBPF_GET_SRC_IP_STATUS_V0;
    HelperPrototype {
        name: "_cf_ebpf_get_src_ip_status_raw",
        return_type: EbpfReturnType::Integer,
        argument_type: [
            EbpfArgumentType::PtrToWritableMem,
            EbpfArgumentType::ConstSize,
            EbpfArgumentType::PtrToWritableMem,
            EbpfArgumentType::ConstSize,
            EbpfArgumentType::DontCare,
        ],
        ..BASE_HELPER_PROTO
    },
    // static int (*set_src_ip_status) (uint8_t status, uint64_t expiry_secs) = (int (*)(uint8_t, uint64_t)) CF_EBPF_SET_SRC_IP_STATUS_V0;
    HelperPrototype {
        name: "set_src_ip_status",
        return_type: EbpfReturnType::Integer,
        argument_type: [
            EbpfArgumentType::Anything,
            EbpfArgumentType::Anything,
            EbpfArgumentType::DontCare,
            EbpfArgumentType::DontCare,
            EbpfArgumentType::DontCare,
        ],
        ..BASE_HELPER_PROTO
    },
    // static int (*_cf_ebpf_get_src_ip_data_raw) (uint64_t *out_data, size_t data_len) = (int (*)(uint64_t*, size_t)) CF_EBPF_GET_SRC_IP_DATA_V0;
    HelperPrototype {
        name: "_cf_ebpf_get_src_ip_data_raw",
        return_type: EbpfReturnType::Integer,
        argument_type: [
            EbpfArgumentType::PtrToWritableMem,
            EbpfArgumentType::ConstSize,
            EbpfArgumentType::DontCare,
            EbpfArgumentType::DontCare,
            EbpfArgumentType::DontCare,
        ],
        ..BASE_HELPER_PROTO
    },
    // static int (*set_src_ip_data) (uint64_t data) = (int (*)(uint64_t)) CF_EBPF_SET_SRC_IP_DATA_V0;
    HelperPrototype {
        name: "set_src_ip_data",
        return_type: EbpfReturnType::Integer,
        argument_type: [
            EbpfArgumentType::Anything,
            EbpfArgumentType::DontCare,
            EbpfArgumentType::DontCare,
            EbpfArgumentType::DontCare,
            EbpfArgumentType::DontCare,
        ],
        ..BASE_HELPER_PROTO
    },
    // static int (*_cf_ebpf_get_flow_data_raw) (uint64_t *out_data, size_t data_len) = (int (*)(uint64_t*, size_t)) CF_EBPF_GET_FLOW_DATA_V0;
    HelperPrototype {
        name: "_cf_ebpf_get_flow_data_raw",
        return_type: EbpfReturnType::Integer,
        argument_type: [
            EbpfArgumentType::PtrToWritableMem,
            EbpfArgumentType::ConstSize,
            EbpfArgumentType::DontCare,
            EbpfArgumentType::DontCare,
            EbpfArgumentType::DontCare,
        ],
        ..BASE_HELPER_PROTO
    },
    // static int (*set_flow_data) (uint64_t data) = (int (*)(uint64_t)) CF_EBPF_SET_FLOW_DATA_V0;
    HelperPrototype {
        name: "set_flow_data",
        return_type: EbpfReturnType::Integer,
        argument_type: [
            EbpfArgumentType::Anything,
            EbpfArgumentType::DontCare,
            EbpfArgumentType::DontCare,
            EbpfArgumentType::DontCare,
            EbpfArgumentType::DontCare,
        ],
        ..BASE_HELPER_PROTO
    },
    // static int64_t (*entropy) (uint8_t *src, size_t src_len) = (int64_t (*)(uint8_t*, size_t)) CF_EBPF_ENTROPY_V0;
    HelperPrototype {
        name: "entropy",
        return_type: EbpfReturnType::Integer,
        argument_type: [
            EbpfArgumentType::PtrToReadableMem,
            EbpfArgumentType::ConstSize,
            EbpfArgumentType::DontCare,
            EbpfArgumentType::DontCare,
            EbpfArgumentType::DontCare,
        ],
        ..BASE_HELPER_PROTO
    },
    // static int (*set_network_analytics_tag)     (uint64_t value) = (int (*)(uint64_t)) CF_EBPF_SET_NETWORK_ANALYTICS_TAG_V0;
    HelperPrototype {
        name: "set_network_analytics_tag",
        return_type: EbpfReturnType::Integer,
        argument_type: [
            EbpfArgumentType::Anything,
            EbpfArgumentType::DontCare,
            EbpfArgumentType::DontCare,
            EbpfArgumentType::DontCare,
            EbpfArgumentType::DontCare,
        ],
        ..BASE_HELPER_PROTO
    },
    // static int (*hash_blake2b512) (uint8_t *src, size_t src_len, uint8_t *dest, size_t dest_len) = (int (*)(uint8_t*, size_t, uint8_t*, size_t)) CF_EBPF_HASH_BLAKE2B_512_V0;
    HelperPrototype {
        name: "hash_blake2b512",
        return_type: EbpfReturnType::Integer,
        argument_type: [
            EbpfArgumentType::PtrToReadableMem,
            EbpfArgumentType::ConstSize,
            EbpfArgumentType::PtrToWritableMem,
            EbpfArgumentType::ConstSize,
            EbpfArgumentType::DontCare,
        ],
        ..BASE_HELPER_PROTO
    },
    // static int (*hmac_blake2b512) (uint8_t *src, size_t src_len, uint8_t *dest, size_t dest_len) = (int (*)(uint8_t*, size_t, uint8_t*, size_t)) CF_EBPF_HMAC_BLAKE2B_512_V0;
    HelperPrototype {
        name: "hmac_blake2b512",
        return_type: EbpfReturnType::Integer,
        argument_type: [
            EbpfArgumentType::PtrToReadableMem,
            EbpfArgumentType::ConstSize,
            EbpfArgumentType::PtrToWritableMem,
            EbpfArgumentType::ConstSize,
            EbpfArgumentType::DontCare,
        ],
        ..BASE_HELPER_PROTO
    },
];
