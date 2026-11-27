# Example programs

Complete Programmable Flow Protection programs that you can upload as they are, or use as a starting point for your own. Each program is explained in the [Cloudflare Developer Documentation](https://developers.cloudflare.com/ddos-protection/advanced-ddos-systems/programmable-flow-protection/examples/).

| Program | What it shows | Features required |
| --- | --- | --- |
| [`header_validation.c`](header_validation.c) | Parse and validate a custom application header, and tag drops for Network Analytics. | None |
| [`rate_limit.c`](rate_limit.c) | Fixed-window rate limit per source IP. | Source IP state |
| [`flow_handshake.c`](flow_handshake.c) | Require each flow to start with a handshake message. | Flow state |
| [`challenge_response.c`](challenge_response.c) | Verify source IPs with a challenge-response exchange. | Challenges, source IP state |
| [`parameter_map_policy.c`](parameter_map_policy.c) | Apply per-source-IP policies that you manage through the API. | Parameter maps |

Features other than the base program are enabled per account. To enable them, contact your account team.

## Build and verify

The examples compile with the same flags that Cloudflare uses when you upload a program, then run through [`pfp-verifier`](../pfp-verifier/). A program that passes here passes the same checks at upload.

Requirements:

- `clang` with the BPF target. Cloudflare compiles programs with `clang` 19, so use the same version to get the same instruction counts. On macOS, Apple clang does not include the BPF target. Install LLVM instead, for example with `brew install llvm@19`.
- A Rust toolchain, to build `pfp-verifier`.

```sh
make                 # compile every example and run pfp-verifier on it
make test            # run the native behavior tests
make check           # both
```

On macOS with Homebrew LLVM, compile the programs with Homebrew `clang` and the native tests with Apple clang:

```sh
make check CLANG="$(brew --prefix llvm@19)/bin/clang" TEST_CC=cc
```

## Behavior tests

Each file in [`tests/`](tests/) compiles an example natively together with [`tests/harness.h`](tests/harness.h), which replaces the helper functions with in-memory mocks of the state tables, challenges, clock, and parameter maps. The tests send packets through every branch of the program and check the verdicts and state changes.

The mocks model the documented helper behavior. They do not replace `pfp-verifier`, or testing with the PCAP debug endpoint and a rule in monitoring mode.

### Test your own program

To test your own program `my_program.c` in this directory, create `tests/test_my_program.c`. The `Makefile` builds and runs every `tests/test_<name>.c` file against `<name>.c`.

```c
#include "../my_program.c"
#include "harness.h"

int main(void) {
    harness_reset();

    /* Build a UDP packet: source IP and port, destination IP and port, payload. */
    h_build_udp(h_ipv4(198, 51, 100, 1), 40000, h_ipv4(192, 0, 2, 10), 27015,
                "GAME", 4);
    CHECK_EQ(h_run(), CF_EBPF_PASS);

    h_build_udp(h_ipv4(198, 51, 100, 1), 40000, h_ipv4(192, 0, 2, 10), 27015,
                "XXXX", 4);
    CHECK_EQ(h_run(), CF_EBPF_DROP);

    return harness_finish("my_program");
}
```

The harness also lets a test control the environment and inspect the results:

| Name | Use |
| --- | --- |
| `h_now` | Value that `timestamp()` returns. Advance it to test expiry and time windows. |
| `h_rand_value` | Value that `rand()` returns. |
| `h_tag` | Last value passed to `set_network_analytics_tag()`. |
| `h_src_entry_for(addr)` | Source IP state entry for an address, with its `status`, `expiry`, and `data`. |
| `h_challenge`, `h_challenge_len`, `h_challenge_calls` | Last challenge payload and the number of `set_challenge()` calls. |
| `h_param_define()`, `h_param_set()` | Define parameter maps and their entries. |
| `h_src_state_enabled`, `h_src_status_enabled`, `h_flow_state_enabled`, `h_params_enabled` | Set to `0` to make the related helper functions return `-5`, as when a feature is not enabled for your account. |
