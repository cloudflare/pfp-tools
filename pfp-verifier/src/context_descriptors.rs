// Copyright (c) 2024 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

//! Context descriptors and program types for the pfp verifier.
//!
//! Each BPF program type has an associated context descriptor that tells prevail
//! the shape of the struct passed in `r1` at program entry. Prevail uses this to
//! track pointer bounds for memory-safety verification of packet data accesses.

use pfp_headers::cf_ebpf_generic_ctx;
use prevail::spec::ebpf_base::EbpfContextDescriptor;
use prevail::spec::type_descriptors::EbpfProgramType;

/// Context descriptor for `cf_ebpf_generic` programs.
///
/// Maps to `cf_ebpf_generic_ctx` from `cf_ebpf_defs.h`:
/// ```c
/// struct cf_ebpf_generic_ctx {
///     uint64_t data;      // offset  0 — pointer to cf_ebpf_packet_data
///     uint64_t data_end;  // offset  8 — one-past-end pointer
///     uint64_t metadata;  // offset 16 — scratch field
/// };
/// ```
pub static CF_EBPF_GENERIC_DESCR: EbpfContextDescriptor = EbpfContextDescriptor {
    size: const {
        let size = size_of::<cf_ebpf_generic_ctx>() as i32;

        // const-time assertion about size of cf_ebpf_generic_ctx
        assert!(
            size == 24,
            "the size of the generic context is expected to be 24 bytes."
        );

        size
    },

    // offsets:
    data: 0,
    end: 8,
    meta: 16,
};

/// Context descriptor for unspecified program types.
///
/// PFP treats unspecified programs the same as generic: if a program's ELF
/// section name doesn't match any known prefix, it still gets full packet-data
/// context pointer tracking.
pub static CF_EBPF_UNSPEC_DESCR: EbpfContextDescriptor = CF_EBPF_GENERIC_DESCR;

/// Returns the program type used as a fallback when no section prefix matches.
pub fn unspec_program_type() -> EbpfProgramType {
    EbpfProgramType {
        name: "unspec".into(),
        context_descriptor: Some(&CF_EBPF_UNSPEC_DESCR),
        platform_specific_data: 0, // only used by prevail's linux-kernel-verifier path, which PFP never invokes
        section_prefixes: vec![],
        is_privileged: false,
    }
}

/// Returns the program type for `cf_ebpf_generic` programs.
///
/// Matches any ELF section whose name starts with `"cf_ebpf_generic"`.
pub fn generic_program_type() -> EbpfProgramType {
    EbpfProgramType {
        name: "cf_ebpf_generic".into(),
        context_descriptor: Some(&CF_EBPF_GENERIC_DESCR),
        platform_specific_data: 0, // only used by prevail's linux-kernel-verifier path, which PFP never invokes
        section_prefixes: vec!["cf_ebpf_generic".into()],
        is_privileged: false,
    }
}

/// Resolves a BPF program type from an ELF section name.
///
/// Iterates the known program types and returns the first whose section prefixes
/// match the start of `section`. Falls back to [`unspec_program_type`] when
/// nothing matches — mirroring `cf_ebpf_verifier_get_program_type` from the
/// original C++ platform.
pub fn get_program_type(section: &str) -> EbpfProgramType {
    let known = [generic_program_type()];

    known
        .into_iter()
        .find(|prog_type| {
            prog_type
                .section_prefixes
                .iter()
                .any(|prefix| section.starts_with(&prefix[..]))
        })
        .unwrap_or_else(unspec_program_type)
}
