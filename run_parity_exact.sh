#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY_REPO="${PY_REPO:-/tmp/NSC_BUILDER_cfx}"
PY_ZTOOLS="$PY_REPO/py/ztools"
PY_ACTIVATE="$PY_REPO/.venv/bin/activate"
TEST_DIR="${TEST_DIR:-/mnt/e/test}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/.qa_suite/exact_script}"
KEYS="${KEYS:-$TEST_DIR/prod.keys}"

BASE_FILE="${BASE_FILE:-$TEST_DIR/Hollow Knight-0100633007D48000--US--v0-.nsp}"
UPD_FILE="${UPD_FILE:-$TEST_DIR/Hollow Knight v1.5.12459 [0100633007D48800][v458752][UPD].nsz}"
SMALL_NSZ="${SMALL_NSZ:-$TEST_DIR/[UPD][v1.0.5][010057D006492800][18.0.0].nsz}"
MERGE_EXTRA="${MERGE_EXTRA:-}"

RUST_BIN=(cargo run --)
FAIL=0

need_file() {
  local p="$1"
  if [[ ! -f "$p" ]]; then
    echo "Missing required file: $p" >&2
    exit 1
  fi
}

log() {
  echo
  echo "==> $1"
}

hash_nca_set() {
  local src_dir="$1"
  local out_file="$2"
  (cd "$src_dir" && find . -type f -name '*.nca' -print0 | sort -z | xargs -0 sha256sum | awk '{print $1}' | sort) >"$out_file"
}

compare_hash_sets() {
  local left="$1"
  local right="$2"
  local label="$3"
  local lcount rcount only_l only_r
  lcount=$(wc -l <"$left")
  rcount=$(wc -l <"$right")
  only_l=$(comm -23 "$left" "$right" | wc -l)
  only_r=$(comm -13 "$left" "$right" | wc -l)
  echo "$label: left=$lcount right=$rcount only_left=$only_l only_right=$only_r"
  if [[ "$only_l" -ne 0 || "$only_r" -ne 0 ]]; then
    FAIL=1
  fi
}

compare_names() {
  local left="$1"
  local right="$2"
  local label="$3"
  local lb rb
  lb="$(basename "$left")"
  rb="$(basename "$right")"
  echo "$label: left='$lb' right='$rb'"
  if [[ "$lb" != "$rb" ]]; then
    FAIL=1
  fi
}

need_file "$KEYS"
need_file "$BASE_FILE"
need_file "$UPD_FILE"
need_file "$SMALL_NSZ"
need_file "$PY_ZTOOLS/squirrel.py"
need_file "$PY_ACTIVATE"

if ! rg -n "os.remove\\(xmlfile\\)" "$PY_ZTOOLS/Fs/Nsp.py" >/dev/null; then
  echo "Python repo likely missing local merge fix in $PY_ZTOOLS/Fs/Nsp.py (expected os.remove(xmlfile))." >&2
  echo "Apply the local fix first, then rerun this script." >&2
  exit 1
fi

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"/{logs,py,rust,cmp}

MERGE_INPUTS=("$BASE_FILE" "$UPD_FILE")
if [[ -n "$MERGE_EXTRA" ]]; then
  while IFS= read -r line; do
    [[ -n "$line" ]] && MERGE_INPUTS+=("$line")
  done <<<"$MERGE_EXTRA"
fi

printf "%s\n" "${MERGE_INPUTS[@]}" >"$OUT_DIR/merge_list.txt"

log "Merge (Rust)"
(
  cd "$ROOT_DIR"
  "${RUST_BIN[@]}" --direct_multi "${MERGE_INPUTS[@]}" \
    --type nsp --ofolder "$OUT_DIR/rust" --keys "$KEYS" \
    >"$OUT_DIR/logs/rust_merge.log" 2>&1
)

log "Merge (Python)"
(
  cd "$PY_ZTOOLS"
  # shellcheck disable=SC1090
  source "$PY_ACTIVATE"
  python squirrel.py -t nsp -tfile "$OUT_DIR/merge_list.txt" -dmul calculate \
    -o "$OUT_DIR/py" -b 65536 \
    >"$OUT_DIR/logs/py_merge.log" 2>&1
)

RUST_MERGED="$(find "$OUT_DIR/rust" -maxdepth 1 -type f -name '*.nsp' | head -n1)"
PY_MERGED="$(find "$OUT_DIR/py" -maxdepth 1 -type f -name '*.nsp' | head -n1)"
need_file "$RUST_MERGED"
need_file "$PY_MERGED"
compare_names "$RUST_MERGED" "$PY_MERGED" "merge_filename"

log "Merge parity (payload compare via split/hash)"
mkdir -p "$OUT_DIR/cmp/merge_split_rust" "$OUT_DIR/cmp/merge_split_py"
(
  cd "$ROOT_DIR"
  "${RUST_BIN[@]}" --splitter "$RUST_MERGED" --ofolder "$OUT_DIR/cmp/merge_split_rust" --keys "$KEYS" >"$OUT_DIR/logs/merge_split_rust.log" 2>&1
  "${RUST_BIN[@]}" --splitter "$PY_MERGED" --ofolder "$OUT_DIR/cmp/merge_split_py" --keys "$KEYS" >"$OUT_DIR/logs/merge_split_py.log" 2>&1
)
hash_nca_set "$OUT_DIR/cmp/merge_split_rust" "$OUT_DIR/cmp/merge_rust.sha"
hash_nca_set "$OUT_DIR/cmp/merge_split_py" "$OUT_DIR/cmp/merge_py.sha"
compare_hash_sets "$OUT_DIR/cmp/merge_rust.sha" "$OUT_DIR/cmp/merge_py.sha" "merge_payload"

log "Split parity (Python --splitter vs Rust --splitter on same merged NSP)"
mkdir -p "$OUT_DIR/cmp/split_py" "$OUT_DIR/cmp/split_rust"
(
  cd "$PY_ZTOOLS"
  # shellcheck disable=SC1090
  source "$PY_ACTIVATE"
  python squirrel.py --splitter "$RUST_MERGED" -o "$OUT_DIR/cmp/split_py" >"$OUT_DIR/logs/py_split.log" 2>&1
)
(
  cd "$ROOT_DIR"
  "${RUST_BIN[@]}" --splitter "$RUST_MERGED" --ofolder "$OUT_DIR/cmp/split_rust" --keys "$KEYS" >"$OUT_DIR/logs/rust_split.log" 2>&1
)
hash_nca_set "$OUT_DIR/cmp/split_rust" "$OUT_DIR/cmp/split_rust.sha"
hash_nca_set "$OUT_DIR/cmp/split_py" "$OUT_DIR/cmp/split_py.sha"
compare_hash_sets "$OUT_DIR/cmp/split_rust.sha" "$OUT_DIR/cmp/split_py.sha" "split_payload"

log "Create parity (same input folder for both tools)"
BASE_TID="$(basename "$BASE_FILE" | grep -oE '[0-9A-Fa-f]{16}' | head -n1 | tr '[:upper:]' '[:lower:]')"
if [[ -z "$BASE_TID" ]]; then
  echo "Could not infer base title id from BASE_FILE: $BASE_FILE" >&2
  exit 1
fi
PY_BASE_DIR="$(find "$OUT_DIR/cmp/split_py" -maxdepth 1 -type d -name "*${BASE_TID}*" | head -n1)"
if [[ -z "$PY_BASE_DIR" ]]; then
  # Squirrel's `-dmul -t nsp` with mixed XCI inputs can omit BASE payload from the output.
  # Fall back to the first split folder for create parity in that case.
  PY_BASE_DIR="$(find "$OUT_DIR/cmp/split_py" -mindepth 1 -maxdepth 1 -type d | sort | head -n1)"
fi
if [[ -z "$PY_BASE_DIR" ]]; then
  echo "Could not locate any python split folder under $OUT_DIR/cmp/split_py" >&2
  exit 1
fi
(
  cd "$ROOT_DIR"
  "${RUST_BIN[@]}" --create "$OUT_DIR/rust/create_base.nsp" --ifolder "$PY_BASE_DIR" --keys "$KEYS" >"$OUT_DIR/logs/rust_create.log" 2>&1
)
(
  cd "$PY_ZTOOLS"
  # shellcheck disable=SC1090
  source "$PY_ACTIVATE"
  python squirrel.py -c "$OUT_DIR/py/create_base.nsp" -ifo "$PY_BASE_DIR" >"$OUT_DIR/logs/py_create.log" 2>&1
)

mkdir -p "$OUT_DIR/cmp/create_split_rust" "$OUT_DIR/cmp/create_split_py"
(
  cd "$ROOT_DIR"
  "${RUST_BIN[@]}" --splitter "$OUT_DIR/rust/create_base.nsp" --ofolder "$OUT_DIR/cmp/create_split_rust" --keys "$KEYS" >"$OUT_DIR/logs/create_split_rust.log" 2>&1
  "${RUST_BIN[@]}" --splitter "$OUT_DIR/py/create_base.nsp" --ofolder "$OUT_DIR/cmp/create_split_py" --keys "$KEYS" >"$OUT_DIR/logs/create_split_py.log" 2>&1
)
hash_nca_set "$OUT_DIR/cmp/create_split_rust" "$OUT_DIR/cmp/create_rust.sha"
hash_nca_set "$OUT_DIR/cmp/create_split_py" "$OUT_DIR/cmp/create_py.sha"
compare_hash_sets "$OUT_DIR/cmp/create_rust.sha" "$OUT_DIR/cmp/create_py.sha" "create_payload"

log "Compress/decompress parity (small NSZ)"
(
  cd "$ROOT_DIR"
  "${RUST_BIN[@]}" --decompress "$SMALL_NSZ" --ofolder "$OUT_DIR/rust" --keys "$KEYS" >"$OUT_DIR/logs/rust_decompress.log" 2>&1
)
RUST_SMALL_NSP="$(ls -t "$OUT_DIR"/rust/*.nsp 2>/dev/null | head -n1 || true)"
need_file "$RUST_SMALL_NSP"

(
  cd "$PY_ZTOOLS"
  # shellcheck disable=SC1090
  source "$PY_ACTIVATE"
  python squirrel.py -dcpr "$SMALL_NSZ" -o "$OUT_DIR/py" >"$OUT_DIR/logs/py_decompress.log" 2>&1
  python squirrel.py -cpr "$RUST_SMALL_NSP" -o "$OUT_DIR/py" >"$OUT_DIR/logs/py_compress.log" 2>&1
)

(
  cd "$ROOT_DIR"
  "${RUST_BIN[@]}" --compress "$RUST_SMALL_NSP" --ofolder "$OUT_DIR/rust" --keys "$KEYS" --level 3 >"$OUT_DIR/logs/rust_compress.log" 2>&1
)

RUST_SMALL_NSZ="$OUT_DIR/rust/$(basename "${RUST_SMALL_NSP%.nsp}.nsz")"
PY_SMALL_NSZ="$OUT_DIR/py/$(basename "${RUST_SMALL_NSP%.nsp}.nsz")"
need_file "$RUST_SMALL_NSZ"
need_file "$PY_SMALL_NSZ"
compare_names "$RUST_SMALL_NSZ" "$PY_SMALL_NSZ" "compress_filename"

mkdir -p "$OUT_DIR/cmp/decomp_rust_nsz" "$OUT_DIR/cmp/decomp_py_nsz"
(
  cd "$ROOT_DIR"
  "${RUST_BIN[@]}" --decompress "$RUST_SMALL_NSZ" --ofolder "$OUT_DIR/cmp/decomp_rust_nsz" --keys "$KEYS" >"$OUT_DIR/logs/decomp_rust_nsz.log" 2>&1
  "${RUST_BIN[@]}" --decompress "$PY_SMALL_NSZ" --ofolder "$OUT_DIR/cmp/decomp_py_nsz" --keys "$KEYS" >"$OUT_DIR/logs/decomp_py_nsz.log" 2>&1
)

mkdir -p "$OUT_DIR/cmp/orig_small_split" "$OUT_DIR/cmp/decomp_rust_small_split" "$OUT_DIR/cmp/decomp_py_small_split"
(
  cd "$ROOT_DIR"
  "${RUST_BIN[@]}" --splitter "$RUST_SMALL_NSP" --ofolder "$OUT_DIR/cmp/orig_small_split" --keys "$KEYS" >"$OUT_DIR/logs/split_orig_small.log" 2>&1
  "${RUST_BIN[@]}" --splitter "$OUT_DIR/cmp/decomp_rust_nsz/$(basename "$RUST_SMALL_NSP")" --ofolder "$OUT_DIR/cmp/decomp_rust_small_split" --keys "$KEYS" >"$OUT_DIR/logs/split_decomp_rust_small.log" 2>&1
  "${RUST_BIN[@]}" --splitter "$OUT_DIR/cmp/decomp_py_nsz/$(basename "$RUST_SMALL_NSP")" --ofolder "$OUT_DIR/cmp/decomp_py_small_split" --keys "$KEYS" >"$OUT_DIR/logs/split_decomp_py_small.log" 2>&1
)
hash_nca_set "$OUT_DIR/cmp/orig_small_split" "$OUT_DIR/cmp/orig_small.sha"
hash_nca_set "$OUT_DIR/cmp/decomp_rust_small_split" "$OUT_DIR/cmp/decomp_rust_small.sha"
hash_nca_set "$OUT_DIR/cmp/decomp_py_small_split" "$OUT_DIR/cmp/decomp_py_small.sha"
compare_hash_sets "$OUT_DIR/cmp/orig_small.sha" "$OUT_DIR/cmp/decomp_rust_small.sha" "decomp_rust_payload"
compare_hash_sets "$OUT_DIR/cmp/orig_small.sha" "$OUT_DIR/cmp/decomp_py_small.sha" "decomp_py_payload"

echo
echo "==== Container sizes (informational) ===="
stat -c '%n\t%s' "$RUST_MERGED" "$PY_MERGED" "$RUST_SMALL_NSZ" "$PY_SMALL_NSZ" "$OUT_DIR/rust/create_base.nsp" "$OUT_DIR/py/create_base.nsp"

echo
if [[ "$FAIL" -eq 0 ]]; then
  echo "Parity suite PASSED (payload + filename checks matched)."
  echo "Artifacts and logs: $OUT_DIR"
  exit 0
else
  echo "Parity suite FAILED (at least one payload or filename comparison differed)." >&2
  echo "Inspect logs/artifacts under: $OUT_DIR" >&2
  exit 1
fi
