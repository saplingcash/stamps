#!/usr/bin/env bash
# Builds the WebAssembly package into ../verifier/wasm (the verifier reads v6 transactions with it), from
# pinned inputs only, so anyone can rebuild the committed file byte for byte:
#
#   - the compiler: rust-toolchain.toml (with the wasm32-unknown-unknown target);
#   - the crates: Cargo.lock (--locked);
#   - the bindings: wasm-bindgen-cli at exactly the version of the wasm-bindgen crate in Cargo.lock
#     (`cargo install wasm-bindgen-cli --version <it> --locked`); no wasm-opt pass;
#   - built from one fixed directory (Cargo hashes a path dependency's location into symbol names), with
#     every source and build path remapped, so the binary carries no path of the machine that built it.
#
#   ./build.sh           # build and copy into ../verifier/wasm
#   ./build.sh --check   # build and fail if it differs from the committed files (CI)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
stamps="$(cd "$here/.." && pwd)"
want="$(awk '/^name = "wasm-bindgen"$/{getline; gsub(/version = |"/, ""); print}' "$here/Cargo.lock")"
bindgen="${WASM_BINDGEN:-wasm-bindgen}"
have="$("$bindgen" --version | awk '{print $2}')"
if [ "$have" != "$want" ]; then
  echo "wasm-bindgen $have found; this build needs exactly $want (cargo install wasm-bindgen-cli --version $want --locked)" >&2
  exit 2
fi
src=/tmp/sapling-stamp-proof-wasm-src
target=/tmp/sapling-stamp-proof-wasm-target
rm -rf "$src" "$target"
mkdir -p "$src"
for d in stamper-core stamp-proof-wasm; do
  (cd "$stamps" && tar --exclude=target -cf - "$d") | tar -xf - -C "$src"
done
out="$(mktemp -d)"
export RUSTFLAGS="--remap-path-prefix=$src=/stamps --remap-path-prefix=$target=/target --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=${RUSTUP_HOME:-$HOME/.rustup}=/rustup"
(cd "$src/stamp-proof-wasm" && CARGO_TARGET_DIR="$target" cargo build --release --locked --target wasm32-unknown-unknown)
"$bindgen" --target web --out-dir "$out" "$target/wasm32-unknown-unknown/release/sapling_stamp_proof_wasm.wasm"
files="sapling_stamp_proof_wasm.js sapling_stamp_proof_wasm.d.ts sapling_stamp_proof_wasm_bg.wasm"
if [ "${1:-}" = "--check" ]; then
  status=0
  for f in $files; do
    if ! cmp -s "$out/$f" "$stamps/verifier/wasm/$f"; then
      echo "$f differs from the committed file: built $(sha256sum < "$out/$f" | cut -c1-64), committed $(sha256sum < "$stamps/verifier/wasm/$f" | cut -c1-64)" >&2
      status=1
    fi
  done
  (cd "$out" && sha256sum sapling_stamp_proof_wasm_bg.wasm) | cmp -s - "$here/SHA256" || { echo "stamp-proof-wasm/SHA256 is not the built file's hash" >&2; status=1; }
  [ $status = 0 ] && echo "the committed WebAssembly is what this source builds: $(sha256sum < "$out/sapling_stamp_proof_wasm_bg.wasm" | cut -c1-64)"
  exit $status
fi
for f in $files; do cp "$out/$f" "$stamps/verifier/wasm/"; done
(cd "$out" && sha256sum sapling_stamp_proof_wasm_bg.wasm) > "$here/SHA256"
cat "$here/SHA256"
