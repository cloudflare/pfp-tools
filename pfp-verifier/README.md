# pfp-verifier

[![Documentation](https://docs.rs/pfp-verifier/badge.svg)](https://docs.rs/pfp-verifier)
[![Crates.io](https://img.shields.io/crates/v/pfp-verifier.svg)](https://crates.io/crates/pfp-verifier)

This crate contains the verifier for programs written for Cloudflare's Programmable Flow 
Protection system. Our verifier is built on top of [prevail](https://github.com/elazarg/prevail-rust).

You may use this crate either as a library (which will provide programmatic access to the 
verifier) or as a binary executable (available via `cargo install pfp-verifier`).
