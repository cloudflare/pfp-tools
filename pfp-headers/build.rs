// Copyright (c) 2024 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

use std::env;
use std::path::PathBuf;

fn main() {
    // Use bindgen to make bindings for ebpf_defs and ebpf_helper headers.
    let bindings = bindgen::Builder::default()
        .trust_clang_mangling(false)
        // The input header we would like to generate
        // bindings for.
        .header("include/cf_ebpf_defs.h")
        .header("include/cf_ebpf_helper.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Write rust bindings for headers.
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
