// Copyright (c) 2024 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

//! Programmable flow protection program verification library.
//!
//! This crate provides a thin wrapper around the rust port of prevail, and provides a command line
//! tool for non-rust languages to use to invoke the verifier.

pub mod config;
mod context_descriptors;
mod helpers;
mod platform;

use crate::config::{MAIN_FUNCTION_NAME, PFP_VERIFIER_OPTIONS};
use crate::platform::PfpEbpfPlatform;
use pfp_headers::{cf_ebpf_return_type_CF_EBPF_DROP, cf_ebpf_return_type_CF_EBPF_PASS};
use prevail::crab::ebpf_domain::{DomainContext, VerificationError};
use prevail::crab::interval::Interval;
use prevail::crab::var_registry::VariableRegistry;
use prevail::fwd_analyzer::analyze;
use prevail::ir::program::{InvalidControlFlow, Program};
use prevail::ir::unmarshal::unmarshal;
use prevail::spec::type_descriptors::ProgramInfo;
use prevail::{elf_loader, ir};
use std::io;
use std::path::Path;
use thiserror::Error;

/// Publicly re-export prevail so that consumers of this library don't have to add
/// another direct dependency on it to handle verifier errors.
pub use prevail;

/// Errors that can occur during PFP program verification.
#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("error encountered during i/o operation: {0}")]
    Io(#[from] io::Error),

    #[error("error during elf unmarshalling: {0}")]
    LoaderUnmarshall(#[from] elf_loader::UnmarshalError),

    #[error("error during intermediate representation unmarshalling: {0}")]
    IrUnmarshall(#[from] ir::unmarshal::UnmarshalError),

    #[error("program could not be converted to control flow graph: {0}")]
    InvalidControlFlow(#[from] InvalidControlFlow),

    /// No function named `cf_ebpf_main` was found in the ELF.
    #[error("elf file does not contain `{MAIN_FUNCTION_NAME}` function")]
    EntryPointNotFound,

    #[error("program failed verification: {0}")]
    VerificationError(VerificationError),

    #[error("program failed verification for unknown reason")]
    UnknownVerificationError,

    #[error("program return value could not be verified ")]
    BadReturnInterval,
}

/// Parse ELF bytes into an ebpf control flow graph.
///
/// Returns the CFG, program metadata, and the pre-CFG instruction count.
fn load_program(bytes: &[u8]) -> Result<(Program, ProgramInfo, usize), VerifyError> {
    let mut platform = PfpEbpfPlatform;

    // Parse all programs from the ELF, then find cf_ebpf_main.
    let raw_progs = elf_loader::read_elf(bytes, "", "", "", &PFP_VERIFIER_OPTIONS, &mut platform)?;

    let raw_prog = raw_progs
        .into_iter()
        .find(|p| p.function_name == MAIN_FUNCTION_NAME)
        .ok_or(VerifyError::EntryPointNotFound)?;

    // Unmarshal instructions, checking for unsupported opcodes and helper calls.
    let mut notes = Vec::new();
    let inst_seq = unmarshal(
        &raw_prog.prog,
        &mut notes,
        &raw_prog.info,
        &platform,
        &PFP_VERIFIER_OPTIONS,
    )?;

    // this is not the max instruction count -- loops are not unrolled or anything here.
    let inst_count = inst_seq.len();

    // Build the control-flow graph.
    let program =
        Program::from_sequence(&inst_seq, &raw_prog.info, &platform, &PFP_VERIFIER_OPTIONS)?;

    Ok((program, raw_prog.info, inst_count))
}

/// Verify a PFP program from ELF bytes.
///
/// On success, returns the number of BPF instructions in the program.
/// On failure, returns a [`VerifyError`] describing what went wrong.
pub fn verify_elf(bytes: &[u8]) -> Result<usize, VerifyError> {
    let (program, info, inst_count) = load_program(bytes)?;

    // Run the abstract interpreter.
    let ctx = DomainContext {
        program_info: &info,
        runtime: &PFP_VERIFIER_OPTIONS.runtime,
        options: &PFP_VERIFIER_OPTIONS,
        platform: &PfpEbpfPlatform,
    };

    let mut registry = VariableRegistry::new();
    let result = analyze(&program, &ctx, &mut registry);

    if result.failed {
        return match result.find_first_error() {
            Some(err) => Err(VerifyError::VerificationError(err)),
            None => Err(VerifyError::UnknownVerificationError),
        };
    }

    // DOSFEAT-708: Assert that exit value is pass or drop.
    // Check the return interval after making sure the program is expected to terminate.
    // we don't care about the return values of programs that have already failed the verifier
    // for other reasons.
    let allow_interval = Interval::from_i64_pair(
        cf_ebpf_return_type_CF_EBPF_PASS as i64,
        cf_ebpf_return_type_CF_EBPF_DROP as i64,
    );

    if !result.exit_value.is_included_in(&allow_interval) {
        return Err(VerifyError::BadReturnInterval);
    }

    Ok(inst_count)
}

/// Verify a PFP program from an ELF file on disk.
///
/// Reads the file and delegates to [`verify_elf`].
pub fn verify_elf_file(path: &Path) -> Result<usize, VerifyError> {
    let bytes = std::fs::read(path)?;
    verify_elf(&bytes)
}

/// Prints a text representation of the cfg (basic blocks with jumps) to stdout.
pub fn print_cfg(bytes: &[u8]) {
    let (program, info, _) = load_program(bytes).expect("failed to load program");

    let stdout = io::stdout();
    let mut out = stdout.lock();

    prevail::printing::print_program(
        &program,
        &info,
        &mut out,
        PFP_VERIFIER_OPTIONS.verbosity_opts.simplify,
    )
    .expect("failed to write CFG text");
}

/// Generate and open the control-flow graph of a PFP program, using graphviz/dot.
/// <https://graphviz.org/>. (you must have the `dot` command line tool installed, I got mine from brew.).
///
/// This function is intended for use debugging verifier errors.
///
/// # Panics
/// - This can panic in a wide variety of cases, so don't use it in prod -- it's intended for local
///   development.
#[cfg(feature = "visualize-cfg")]
#[cfg(debug_assertions)] // again this is only for debugging
pub fn open_cfg_dot(bytes: &[u8]) {
    let (program, _, _) = load_program(bytes).expect("failed to load program");
    let mut dot_file = tempfile::NamedTempFile::new().unwrap();

    let (_, png_path) = tempfile::Builder::new()
        .suffix(".png")
        .tempfile()
        .unwrap()
        // we have to persist the file so that it can be rendered and opened without getting erased.
        .keep()
        .unwrap();

    // write dot file
    prevail::printing::print_dot(&program, &mut dot_file).expect("failed to write DOT graph");

    // render dot file.
    std::process::Command::new("dot")
        .arg("-Tpng")
        .arg("-o")
        .arg(&png_path)
        .arg(dot_file.path())
        .status()
        .unwrap();

    open::that(png_path.as_os_str()).unwrap();
}
