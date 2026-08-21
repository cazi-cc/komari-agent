#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
installer="${repo_root}/install.sh"

bash -n "${installer}"

expected='[ "$need_nping" -eq 0 ] || apk add --no-cache nmap-nping'
if ! grep -Fq "${expected}" "${installer}"; then
    echo "install.sh must install Alpine nping from nmap-nping" >&2
    exit 1
fi

if grep -Eq 'apk add( --no-cache)? nmap([[:space:]]|$)' "${installer}"; then
    echo "install.sh must not use Alpine's main nmap package as the nping provider" >&2
    exit 1
fi

echo "Installer syntax and Alpine nping package mapping are valid."
