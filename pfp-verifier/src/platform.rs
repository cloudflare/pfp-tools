// Copyright (c) 2024 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

//! Definition of ebpf platform used for pfp verification.

use crate::context_descriptors;
use crate::helpers::HELPER_PROTOS;
use prevail::elf_loader::UnmarshalError;
use prevail::linux::spec_prototypes::HelperPrototype;
use prevail::platform::EbpfPlatform;
use prevail::spec::config::EbpfVerifierOptions;
use prevail::spec::type_descriptors::{EbpfMapDescriptor, EbpfMapType, EbpfProgramType};

/// Pfp specific platform details for verifier.
pub struct PfpEbpfPlatform;

impl EbpfPlatform for PfpEbpfPlatform {
    fn get_program_type(&self, section: &str, _: &str) -> EbpfProgramType {
        context_descriptors::get_program_type(section)
    }

    /// # Panics
    /// - If `n` is not a valid/usable helper index.
    fn get_helper_prototype(&self, n: i32) -> &HelperPrototype {
        if !self.is_helper_usable(n) {
            panic!("invalid helper prototype access");
        }

        &HELPER_PROTOS[n as usize]
    }

    fn is_helper_usable(&self, n: i32) -> bool {
        let i = n as usize;
        n >= 0 && i < HELPER_PROTOS.len() && !HELPER_PROTOS[i].unsupported
    }

    /// # Panics
    /// Always -- pfp doesn't support maps
    fn map_record_size(&self) -> usize {
        panic!("maps not supported in pfp");
    }

    /// # Panics
    /// Always -- pfp doesn't support maps
    fn parse_maps_section(
        &mut self,
        _: &mut Vec<EbpfMapDescriptor>,
        _: &[u8],
        _: usize,
        _: usize,
        _: &EbpfVerifierOptions,
    ) {
        panic!("maps not supported in pfp");
    }

    /// # Panics
    /// Always -- pfp doesn't support maps
    fn resolve_inner_map_references(
        &self,
        _: &mut Vec<EbpfMapDescriptor>,
    ) -> Result<(), UnmarshalError> {
        panic!("maps not supported in pfp");
    }

    /// # Panics
    /// Always -- pfp doesn't support maps
    fn get_map_descriptor(&self, _: i32) -> Option<&EbpfMapDescriptor> {
        panic!("maps not supported in pfp");
    }

    /// # Panics
    /// Always -- pfp doesn't support maps
    fn get_map_type(&self, _: u32) -> EbpfMapType {
        panic!("maps not supported in pfp");
    }

    fn supported_conformance_groups(&self) -> u32 {
        // https://docs.kernel.org/bpf/standardization/instruction-set.html#conformance-groups
        // https://www.rfc-editor.org/rfc/rfc9669.html#helper-functions
        // I think we just return the default linux conformance groups here and we're fine.
        prevail::linux::linux_platform::conformance_groups::DEFAULT_GROUPS
    }
}
