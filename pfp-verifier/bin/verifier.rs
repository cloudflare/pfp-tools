// Copyright (c) 2024 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

use clap::Parser;
use pfp_verifier::verify_elf_file;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    about = "Verify a PFP eBPF program ELF file",
    author = "Cloudflare, Inc.",
    version
)]
struct Cli {
    /// ELF file to verify.
    path: PathBuf,
}

fn main() -> ExitCode {
    let args = Cli::parse();

    match verify_elf_file(&args.path) {
        Ok(inst_count) => {
            println!("{inst_count}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
