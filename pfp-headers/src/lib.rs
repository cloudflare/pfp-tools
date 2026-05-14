// Copyright (c) 2024 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

//! Small wrapper crate that generates bindings against the pfp headers.

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
#[allow(unsafe_op_in_unsafe_fn)]
#[allow(clippy::useless_transmute)]
#[allow(clippy::ptr_offset_with_cast)]
#[allow(clippy::missing_safety_doc)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

/// Public re-export of generated bindings.
pub use bindings::*;
