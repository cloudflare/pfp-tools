// Copyright (c) 2024 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

//! Definition of options passed to prevail, and PFP-wide verification constants.

use prevail::spec::config::{
    EbpfRuntimeConfig, EbpfVerifierOptions, PrepareCfgOptions, VerbosityOptions,
};

/// The name of the entry-point function every PFP program must export.
pub const MAIN_FUNCTION_NAME: &str = "cf_ebpf_main";

/// Maximum stack space (bytes) per call frame. Matches `-bpf-stack-size=8192`
/// split across [`MAX_CALL_STACK_FRAMES`] frames (2048 × 4 = 8192).
pub const STACK_FRAME_SIZE: i32 = 2048;

/// Maximum call-stack depth. Together with [`STACK_FRAME_SIZE`] this gives
/// a total verified stack of 8 KiB, matching the clang compilation flag.
pub const MAX_CALL_STACK_FRAMES: i32 = 4;

/// We use these prevail options when verifying every single pfp program.
pub const PFP_VERIFIER_OPTIONS: EbpfVerifierOptions = EbpfVerifierOptions {
    // options for constructing control flow graph
    cfg_opts: PrepareCfgOptions {
        // make sure the program terminates.
        check_for_termination: true,

        // not sure what this one does but prevail defaults it to true.
        // https://github.com/vbpf/prevail/blob/ac03ef646cfeeaab790a15e04ed833f182ed7f24/src/config.hpp#L13
        must_have_exit: true,
    },

    // we don't use maps, so not sure if this value here is even used anywhere.
    // prevail defaults to true, so that's what we use here.
    mock_map_fds: true,

    runtime: EbpfRuntimeConfig {
        // we do want extra strictness around potential runtime failures.
        strict: true,

        // we do not want to allow division by zero.
        allow_division_by_zero: false,

        // not really sure what this one does, it's true by default in prevail though.
        // https://github.com/elazarg/prevail-rust/blob/c196fe2c802725b334f6ea15137763ed20686c4b/src/spec/config.rs#L101
        setup_constraints: true,

        // if we're running on a big-endian system, assume the program was compiled on a big endian system.
        // in practice, we'll probably never run into this.
        big_endian: cfg!(target_endian = "big"),

        subprogram_stack_size: STACK_FRAME_SIZE,
        max_call_stack_frames: MAX_CALL_STACK_FRAMES,
        max_packet_size: EbpfRuntimeConfig::DEFAULT_MAX_PACKET_SIZE,
    },

    verbosity_opts: VerbosityOptions {
        // prevail default is true here, turns unconditional chains into basic blocks.
        simplify: true,

        // prevail default is false here, prints invariants for each basic block.
        print_invariants: false,

        // we do want to print failures during verification
        print_failures: true,

        // when printing cfg, print line info for each instruction
        // we set this to true, not sure if necessary. prevail default is false.
        print_line_info: true,

        // dump all btf types as json, prevail default is false.
        dump_btf_types_json: false,

        // collect instruction dependencies.
        // see https://github.com/vbpf/prevail/blob/1a19d6fa01ced5ac88cb9e914d8620f1c95dfb02/src/config.hpp#L29
        // prevail default is false.
        collect_instruction_deps: false,
    },
};
