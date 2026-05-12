#!/bin/bash
# Source this file before running Go tests: source plan/lean-authz-ffi/env.sh
# Must be run from the kubernetes repo root.

set -e

# Try lean on PATH, fall back to elan location
LEAN_BIN="${LEAN_BIN:-$(command -v lean 2>/dev/null || echo "${HOME}/.elan/bin/lean")}"
LEAN_TOOLCHAIN="$("${LEAN_BIN}" --print-prefix)"
LEAN_LIBDIR="${LEAN_TOOLCHAIN}/lib/lean"
LEAN_INCDIR="${LEAN_TOOLCHAIN}/include"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LEAN_AUTHZ_LIBDIR="${SCRIPT_DIR}/../lean-authz/.lake/build/lib"

if [ ! -f "${LEAN_AUTHZ_LIBDIR}/liblean_x2dauthz_TranspiledAuthzFFI.a" ]; then
    echo "ERROR: Lean static libraries not found. Run:"
    echo "  cd plan/lean-authz && lake build TranspiledAuthzFFI:static TranspiledAuthz:static"
    exit 1
fi

export CGO_CFLAGS="-I${LEAN_INCDIR}"
export CGO_LDFLAGS="-L${LEAN_AUTHZ_LIBDIR} -llean_x2dauthz_TranspiledAuthzFFI -llean_x2dauthz_TranspiledAuthz -L${LEAN_LIBDIR} -lLean -lStd -lInit -lleanrt -L/opt/homebrew/lib -lgmp -luv -lc -lm -lstdc++ -framework CoreFoundation"

echo "CGO_CFLAGS=${CGO_CFLAGS}"
echo "CGO_LDFLAGS=${CGO_LDFLAGS}"
echo "Environment set. Run: cd plan/lean-authz-ffi && GOWORK=off go test -v -count=1 ."
