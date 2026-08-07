# pfp-tools

This repository holds the verifier and headers used for customer Programmable Flow Protection programs.

For more information regarding Programmable Flow Protection, read the [blog post] and/or look at the
[Cloudflare Developer Documentation].

## Release process

Releases are triggered by merging a version bump to `main`. Dependency or source changes that keep
the current package version do not create a release.

1. Open a pull request that updates the shared version in `[workspace.package]` and both versions in
   `[workspace.dependencies]` in `Cargo.toml`. `pfp-headers` and `pfp-verifier` must use the same
   version.
2. Update `pfp-headers/RELEASE_NOTES.md` and `pfp-verifier/RELEASE_NOTES.md` as appropriate.
3. Update `Cargo.lock` and run the workspace checks. CI verifies the package set, shared version,
   lockfile, and the `pfp-verifier` requirement on `pfp-headers`.
4. Merge the pull request after CI passes. Do not publish the crates or create the release tag
   manually.

After the merge, the publish workflow compares the workspace version with crates.io. For a new
version, it publishes `pfp-headers` first and then `pfp-verifier`. Once both published archives are
verified to come from the same commit, the workflow creates an annotated tag named after the version,
for example `0.4.0`.

If the workflow is interrupted, rerun it from `main` with `workflow_dispatch`. It safely resumes a
partial release from the source commit recorded in the already-published crate. If the version is
already fully published, the workflow only verifies and reconciles the release tag.

[blog post]: https://blog.cloudflare.com/programmable-flow-protection/
[Cloudflare Developer Documentation]: https://developers.cloudflare.com/ddos-protection/advanced-ddos-systems/overview/programmable-flow-protection/
