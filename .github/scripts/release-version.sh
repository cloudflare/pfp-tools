#!/usr/bin/env bash

set -euo pipefail

metadata="$(cargo metadata --locked --no-deps --format-version 1)"

mapfile -t package_names < <(
  jq -r '.packages[].name' <<<"${metadata}" |
    sort
)
if [[ "${package_names[*]}" != "pfp-headers pfp-verifier" ]]; then
  echo "workspace must contain exactly pfp-headers and pfp-verifier: ${package_names[*]}" >&2
  exit 1
fi

mapfile -t versions < <(
  jq -r '.packages[] | select(.name == "pfp-headers" or .name == "pfp-verifier") | .version' <<<"${metadata}" |
    sort -u
)
if [[ ${#versions[@]} -ne 1 ]]; then
  echo "pfp-headers and pfp-verifier must have one shared version: ${versions[*]}" >&2
  exit 1
fi

version="${versions[0]}"
headers_requirement="$(
  jq -r '
    .packages[] |
    select(.name == "pfp-verifier") |
    .dependencies[] |
    select(.name == "pfp-headers") |
    .req
  ' <<<"${metadata}"
)"
if [[ "${headers_requirement}" != "^${version}" ]]; then
  echo "pfp-verifier requires pfp-headers ${headers_requirement}, expected ^${version}" >&2
  exit 1
fi

printf '%s\n' "${version}"
