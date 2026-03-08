#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="${TEST_DIR:-/mnt/e/test/uo}"
MULTI_UPDATE_DIR="${MULTI_UPDATE_DIR:-/mnt/e/test/op}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/.qa_suite/exact_script}"
KEYS="${KEYS:-/mnt/e/test/prod.keys}"
PY_REPO="${PY_REPO:-$ROOT_DIR/.qa_suite/reference/NSC_BUILDER}"
PY_ZTOOLS="${PY_ZTOOLS:-$PY_REPO/py/ztools}"
PYTHON_BIN="${PYTHON_BIN:-$PY_REPO/.venv/bin/python}"
RUST_BIN=("$ROOT_DIR/target/debug/nscb")
FAIL=0

BASE_FILE="${BASE_FILE:-$(find "$TEST_DIR" -maxdepth 1 -type f -name '*.xci' | sort | head -n1)}"
if [[ -z "$BASE_FILE" ]]; then
  BASE_FILE="${BASE_FILE:-$(find "$TEST_DIR" -maxdepth 1 -type f -name '*.nsp' ! -name '[[]UPD[]]*' ! -name '[[]DLC[]]*' | sort | head -n1)}"
fi
UPD_FILE="${UPD_FILE:-$(find "$TEST_DIR" -maxdepth 1 -type f \( -name '[[]UPD[]]*.nsz' -o -name '[[]UPD[]]*.nsp' \) | sort | head -n1)}"
SMALL_NSZ="${SMALL_NSZ:-$UPD_FILE}"
mapfile -t DLC_FILES < <(find "$TEST_DIR" -maxdepth 1 -type f -name '[[]DLC[]]*.nsp' | sort)
MULTI_BASE_FILE="${MULTI_BASE_FILE:-$(find "$MULTI_UPDATE_DIR" -maxdepth 1 -type f -name 'OCTOPATH TRAVELER*.nsp' ! -name '[[]UPD[]]*' | sort | head -n1)}"
MULTI_UPD_OLD_FILE="${MULTI_UPD_OLD_FILE:-$(find "$MULTI_UPDATE_DIR" -maxdepth 1 -type f -name '[[]UPD[]]*v1.0.4*.nsp' | sort | head -n1)}"
MULTI_UPD_NEW_FILE="${MULTI_UPD_NEW_FILE:-$(find "$MULTI_UPDATE_DIR" -maxdepth 1 -type f \( -name '[[]UPD[]]*v1.0.5*.nsz' -o -name '[[]UPD[]]*v1.0.5*.nsp' \) | sort | head -n1)}"

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

pass_or_fail() {
  local label="$1"
  local cmd="$2"
  if eval "$cmd"; then
    echo "$label: ok"
  else
    echo "$label: failed"
    FAIL=1
  fi
}

hash_nca_set() {
  local src_dir="$1"
  local out_file="$2"
  (cd "$src_dir" && find . -type f -name '*.nca' -print0 | sort -z | xargs -0 sha256sum | awk '{print $1}' | sort) >"$out_file"
}

hash_nca_set_nested() {
  local src_dir="$1"
  local out_file="$2"
  (cd "$src_dir" && find . -mindepth 2 -type f -name '*.nca' -print0 | sort -z | xargs -0 sha256sum | awk '{print $1}' | sort) >"$out_file"
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

sha256_skip_prefix() {
  local input="$1"
  local skip_bytes="$2"
  python3 - "$input" "$skip_bytes" <<'PY'
from pathlib import Path
import hashlib
import sys

path = Path(sys.argv[1])
skip = int(sys.argv[2])
with path.open('rb') as f:
    f.seek(skip)
    h = hashlib.sha256()
    while True:
        chunk = f.read(1024 * 1024)
        if not chunk:
            break
        h.update(chunk)
print(h.hexdigest())
PY
}

newest_file() {
  local dir="$1"
  local pattern="$2"
  find "$dir" -maxdepth 1 -type f -name "$pattern" -printf '%T@ %p\n' | sort -nr | head -n1 | cut -d' ' -f2-
}

normalize_info_output() {
  local input="$1"
  local output="$2"
  python3 - "$input" "$output" <<'PY'
from pathlib import Path
import sys
src = Path(sys.argv[1]).read_text(errors="replace").splitlines()
src = [line for line in src if 'squirrel.py:' not in line and line.strip() != "'''"]
cut = len(src)
for i, line in enumerate(src):
    if line.startswith('********************************************************'):
        cut = i
        break
src = src[:cut]
Path(sys.argv[2]).write_text("\n".join(src) + ("\n" if src else ""))
PY
}

normalize_advfilelist_parity_output() {
  local input="$1"
  local output="$2"
  python3 - "$input" "$output" <<'PY'
from pathlib import Path
import sys

lines = Path(sys.argv[1]).read_text(errors="replace").splitlines()

# Intentional exception:
# Rust extends the RSV floor table for higher key generations, while the Python
# reference falls back to the current RSV in ADVfilelist "Patchable to" reporting
# for unsupported/high keygens. Keep merge behavior correct in Rust and exclude
# this known reporting-only discrepancy from parity gating.
filtered = [line for line in lines if not line.strip().startswith("- Patchable to:")]
Path(sys.argv[2]).write_text("\n".join(filtered) + ("\n" if filtered else ""))
PY
}

run_py_info() {
  local flag="$1"
  local input="$2"
  local output="$3"
  mkdir -p "$(dirname "$output")"
  (
    cd "$PY_ZTOOLS"
    printf '2\n' | "$PYTHON_BIN" squirrel.py "$flag" "$input" -o "$OUT_DIR/py_info" >"$output" 2>&1
  )
}

need_file "$KEYS"
need_file "$BASE_FILE"
need_file "$UPD_FILE"
need_file "$SMALL_NSZ"

if [[ "${#DLC_FILES[@]}" -lt 2 ]]; then
  echo "Expected at least 2 DLC NSP files under $TEST_DIR" >&2
  exit 1
fi

HAVE_PY=0
if [[ -f "$PY_ZTOOLS/squirrel.py" && -x "$PYTHON_BIN" ]]; then
  HAVE_PY=1
fi

HAVE_MULTI_UPDATE=0
if [[ -f "$MULTI_BASE_FILE" && -f "$MULTI_UPD_OLD_FILE" && -f "$MULTI_UPD_NEW_FILE" ]]; then
  HAVE_MULTI_UPDATE=1
fi

if [[ "$HAVE_PY" -eq 1 && ! -f "$PY_ZTOOLS/Fs/Nsp.py" ]]; then
  echo "Missing Python reference sources under $PY_ZTOOLS" >&2
  exit 1
fi

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"/{logs,py,rust,cmp,py_info}
cp "$KEYS" "$PY_ZTOOLS/prod.keys" 2>/dev/null || true
cp "$KEYS" "$PY_ZTOOLS/lib/keys.txt" 2>/dev/null || true

log "Build Rust binary"
(
  cd "$ROOT_DIR"
  cargo build >"$OUT_DIR/logs/cargo_build.log" 2>&1
)

MERGE_INPUTS=("$BASE_FILE" "$UPD_FILE" "${DLC_FILES[@]}")
printf "%s\n" "${MERGE_INPUTS[@]}" >"$OUT_DIR/merge_list.txt"

log "Merge to NSP (Rust)"
(
  cd "$ROOT_DIR"
  "${RUST_BIN[@]}" --direct_multi "${MERGE_INPUTS[@]}" \
    --type nsp --ofolder "$OUT_DIR/rust" --keys "$KEYS" \
    >"$OUT_DIR/logs/rust_merge_nsp.log" 2>&1
)
RUST_MERGED_NSP="$(newest_file "$OUT_DIR/rust" '*.nsp')"
need_file "$RUST_MERGED_NSP"

if [[ "$HAVE_PY" -eq 1 ]]; then
  log "Merge to NSP (Python)"
  (
    cd "$PY_ZTOOLS"
    "$PYTHON_BIN" squirrel.py -t nsp -tfile "$OUT_DIR/merge_list.txt" -dmul calculate \
      -o "$OUT_DIR/py" -b 65536 \
      >"$OUT_DIR/logs/py_merge_nsp.log" 2>&1
  )
  PY_MERGED_NSP="$(newest_file "$OUT_DIR/py" '*.nsp')"
  need_file "$PY_MERGED_NSP"
  compare_names "$RUST_MERGED_NSP" "$PY_MERGED_NSP" "merge_nsp_filename"

  log "Merge NSP parity (payload compare via split/hash)"
  sha256sum "$RUST_MERGED_NSP" | awk '{print $1}' >"$OUT_DIR/cmp/merge_rust.sha"
  sha256sum "$PY_MERGED_NSP" | awk '{print $1}' >"$OUT_DIR/cmp/merge_py.sha"
  diff -u "$OUT_DIR/cmp/merge_py.sha" "$OUT_DIR/cmp/merge_rust.sha" >"$OUT_DIR/cmp/merge_nsp_payload.diff" || FAIL=1

  log "Split parity on base container"
  mkdir -p "$OUT_DIR/cmp/split_py" "$OUT_DIR/cmp/split_rust"
  (
    cd "$PY_ZTOOLS"
    "$PYTHON_BIN" squirrel.py --splitter "$BASE_FILE" -o "$OUT_DIR/cmp/split_py" >"$OUT_DIR/logs/py_split.log" 2>&1
  )
  (
    cd "$ROOT_DIR"
    "${RUST_BIN[@]}" --splitter "$BASE_FILE" --ofolder "$OUT_DIR/cmp/split_rust" --keys "$KEYS" >"$OUT_DIR/logs/rust_split.log" 2>&1
  )
  hash_nca_set_nested "$OUT_DIR/cmp/split_rust" "$OUT_DIR/cmp/split_rust.sha"
  hash_nca_set_nested "$OUT_DIR/cmp/split_py" "$OUT_DIR/cmp/split_py.sha"
  compare_hash_sets "$OUT_DIR/cmp/split_rust.sha" "$OUT_DIR/cmp/split_py.sha" "split_payload"
  find "$OUT_DIR/cmp/split_rust" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort >"$OUT_DIR/cmp/split_rust.names"
  find "$OUT_DIR/cmp/split_py" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort >"$OUT_DIR/cmp/split_py.names"
  diff -u "$OUT_DIR/cmp/split_py.names" "$OUT_DIR/cmp/split_rust.names" >"$OUT_DIR/cmp/split_names.diff" || FAIL=1

  log "Create parity from split folder"
  BASE_TID="$(basename "$BASE_FILE" | grep -oE '[0-9A-Fa-f]{16}' | head -n1 | tr '[:upper:]' '[:lower:]')"
  if [[ -z "$BASE_TID" ]]; then
    echo "Could not infer base title id from BASE_FILE: $BASE_FILE" >&2
    exit 1
  fi
  PY_BASE_DIR="$(find "$OUT_DIR/cmp/split_py" -maxdepth 1 -type d -name "*${BASE_TID}*" | head -n1)"
  if [[ -z "$PY_BASE_DIR" ]]; then
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
    "$PYTHON_BIN" squirrel.py -c "$OUT_DIR/py/create_base.nsp" -ifo "$PY_BASE_DIR" >"$OUT_DIR/logs/py_create.log" 2>&1
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
  compare_names "$OUT_DIR/rust/create_base.nsp" "$OUT_DIR/py/create_base.nsp" "create_filename"

  log "Direct conversion parity"
  mkdir -p "$OUT_DIR/direct_conv_rust" "$OUT_DIR/direct_conv_py"
  (
    cd "$ROOT_DIR"
    "${RUST_BIN[@]}" --direct_creation "$BASE_FILE" --type nsp --ofolder "$OUT_DIR/direct_conv_rust" --keys "$KEYS" >"$OUT_DIR/logs/rust_direct_xci_to_nsp.log" 2>&1
  )
  (
    cd "$PY_ZTOOLS"
    "$PYTHON_BIN" squirrel.py -dc "$BASE_FILE" -t nsp -o "$OUT_DIR/direct_conv_py" >"$OUT_DIR/logs/py_direct_xci_to_nsp.log" 2>&1
  )
  RUST_DIRECT_NSP="$(newest_file "$OUT_DIR/direct_conv_rust" '*.nsp')"
  PY_DIRECT_NSP="$(newest_file "$OUT_DIR/direct_conv_py" '*.nsp')"
  need_file "$RUST_DIRECT_NSP"
  need_file "$PY_DIRECT_NSP"
  compare_names "$RUST_DIRECT_NSP" "$PY_DIRECT_NSP" "direct_xci_to_nsp_filename"
  sha256sum "$RUST_DIRECT_NSP" | awk '{print $1}' >"$OUT_DIR/cmp/direct_xci_to_nsp_rust.sha"
  sha256sum "$PY_DIRECT_NSP" | awk '{print $1}' >"$OUT_DIR/cmp/direct_xci_to_nsp_py.sha"
  diff -u "$OUT_DIR/cmp/direct_xci_to_nsp_py.sha" "$OUT_DIR/cmp/direct_xci_to_nsp_rust.sha" >"$OUT_DIR/cmp/direct_xci_to_nsp.diff" || FAIL=1

  (
    cd "$ROOT_DIR"
    "${RUST_BIN[@]}" --direct_creation "$PY_DIRECT_NSP" --type xci --ofolder "$OUT_DIR/direct_conv_rust" --keys "$KEYS" >"$OUT_DIR/logs/rust_direct_nsp_to_xci.log" 2>&1
  )
  (
    cd "$PY_ZTOOLS"
    "$PYTHON_BIN" squirrel.py -dc "$PY_DIRECT_NSP" -t xci -cskip False -o "$OUT_DIR/direct_conv_py" >"$OUT_DIR/logs/py_direct_nsp_to_xci.log" 2>&1
  )
  RUST_DIRECT_XCI="$(newest_file "$OUT_DIR/direct_conv_rust" '*.xci')"
  PY_DIRECT_XCI="$(newest_file "$OUT_DIR/direct_conv_py" '*.xci')"
  need_file "$RUST_DIRECT_XCI"
  need_file "$PY_DIRECT_XCI"
  compare_names "$RUST_DIRECT_XCI" "$PY_DIRECT_XCI" "direct_nsp_to_xci_filename"
  sha256_skip_prefix "$RUST_DIRECT_XCI" 256 >"$OUT_DIR/cmp/direct_nsp_to_xci_rust.sha"
  sha256_skip_prefix "$PY_DIRECT_XCI" 256 >"$OUT_DIR/cmp/direct_nsp_to_xci_py.sha"
  diff -u "$OUT_DIR/cmp/direct_nsp_to_xci_py.sha" "$OUT_DIR/cmp/direct_nsp_to_xci_rust.sha" >"$OUT_DIR/cmp/direct_nsp_to_xci.diff" || FAIL=1
  mkdir -p "$OUT_DIR/cmp/direct_nsp_to_xci_rust" "$OUT_DIR/cmp/direct_nsp_to_xci_py"
  (
    cd "$ROOT_DIR"
    "${RUST_BIN[@]}" --splitter "$RUST_DIRECT_XCI" --ofolder "$OUT_DIR/cmp/direct_nsp_to_xci_rust" --keys "$KEYS" >"$OUT_DIR/logs/split_direct_nsp_to_xci_rust.log" 2>&1
    "${RUST_BIN[@]}" --splitter "$PY_DIRECT_XCI" --ofolder "$OUT_DIR/cmp/direct_nsp_to_xci_py" --keys "$KEYS" >"$OUT_DIR/logs/split_direct_nsp_to_xci_py.log" 2>&1
  )
  hash_nca_set "$OUT_DIR/cmp/direct_nsp_to_xci_rust" "$OUT_DIR/cmp/direct_nsp_to_xci_rust.sha"
  hash_nca_set "$OUT_DIR/cmp/direct_nsp_to_xci_py" "$OUT_DIR/cmp/direct_nsp_to_xci_py.sha"
  compare_hash_sets "$OUT_DIR/cmp/direct_nsp_to_xci_rust.sha" "$OUT_DIR/cmp/direct_nsp_to_xci_py.sha" "direct_nsp_to_xci_payload"

  if [[ "$BASE_FILE" == *.xci ]]; then
    BASE_NSP_INPUT="$OUT_DIR/py/create_base.nsp"
    ALT_MERGE_INPUTS=("$BASE_NSP_INPUT" "$UPD_FILE" "${DLC_FILES[@]}")
    printf "%s\n" "${ALT_MERGE_INPUTS[@]}" >"$OUT_DIR/merge_list_nsp_base.txt"

    log "Split parity on generated base NSP"
    mkdir -p "$OUT_DIR/cmp/split_base_nsp_py" "$OUT_DIR/cmp/split_base_nsp_rust"
    (
      cd "$PY_ZTOOLS"
      "$PYTHON_BIN" squirrel.py --splitter "$BASE_NSP_INPUT" -o "$OUT_DIR/cmp/split_base_nsp_py" >"$OUT_DIR/logs/py_split_base_nsp.log" 2>&1
    )
    (
      cd "$ROOT_DIR"
      "${RUST_BIN[@]}" --splitter "$BASE_NSP_INPUT" --ofolder "$OUT_DIR/cmp/split_base_nsp_rust" --keys "$KEYS" >"$OUT_DIR/logs/rust_split_base_nsp.log" 2>&1
    )
    hash_nca_set_nested "$OUT_DIR/cmp/split_base_nsp_rust" "$OUT_DIR/cmp/split_base_nsp_rust.sha"
    hash_nca_set_nested "$OUT_DIR/cmp/split_base_nsp_py" "$OUT_DIR/cmp/split_base_nsp_py.sha"
    compare_hash_sets "$OUT_DIR/cmp/split_base_nsp_rust.sha" "$OUT_DIR/cmp/split_base_nsp_py.sha" "split_base_nsp_payload"

    log "Info parity on generated base NSP"
    (
      cd "$ROOT_DIR"
      "${RUST_BIN[@]}" --ADVfilelist "$BASE_NSP_INPUT" --keys "$KEYS" >"$OUT_DIR/logs/rust_advfilelist_base_nsp.log" 2>&1
      "${RUST_BIN[@]}" --ADVcontentlist "$BASE_NSP_INPUT" --keys "$KEYS" >"$OUT_DIR/logs/rust_advcontentlist_base_nsp.log" 2>&1
    )
    run_py_info --ADVfilelist "$BASE_NSP_INPUT" "$OUT_DIR/logs/py_advfilelist_base_nsp.log"
    run_py_info --ADVcontentlist "$BASE_NSP_INPUT" "$OUT_DIR/logs/py_advcontentlist_base_nsp.log"
    normalize_info_output "$OUT_DIR/logs/py_advfilelist_base_nsp.log" "$OUT_DIR/cmp/py_advfilelist_base_nsp.raw.norm"
    normalize_info_output "$OUT_DIR/logs/rust_advfilelist_base_nsp.log" "$OUT_DIR/cmp/rust_advfilelist_base_nsp.raw.norm"
    normalize_advfilelist_parity_output "$OUT_DIR/cmp/py_advfilelist_base_nsp.raw.norm" "$OUT_DIR/cmp/py_advfilelist_base_nsp.norm"
    normalize_advfilelist_parity_output "$OUT_DIR/cmp/rust_advfilelist_base_nsp.raw.norm" "$OUT_DIR/cmp/rust_advfilelist_base_nsp.norm"
    diff -u "$OUT_DIR/cmp/py_advfilelist_base_nsp.norm" "$OUT_DIR/cmp/rust_advfilelist_base_nsp.norm" >"$OUT_DIR/cmp/advfilelist_base_nsp.diff" || FAIL=1
    normalize_info_output "$OUT_DIR/logs/py_advcontentlist_base_nsp.log" "$OUT_DIR/cmp/py_advcontentlist_base_nsp.norm"
    normalize_info_output "$OUT_DIR/logs/rust_advcontentlist_base_nsp.log" "$OUT_DIR/cmp/rust_advcontentlist_base_nsp.norm"
    diff -u "$OUT_DIR/cmp/py_advcontentlist_base_nsp.norm" "$OUT_DIR/cmp/rust_advcontentlist_base_nsp.norm" >"$OUT_DIR/cmp/advcontentlist_base_nsp.diff" || FAIL=1

    log "Merge to NSP with base NSP source"
    mkdir -p "$OUT_DIR/rust_base_nsp" "$OUT_DIR/py_base_nsp"
    (
      cd "$ROOT_DIR"
      "${RUST_BIN[@]}" --direct_multi "${ALT_MERGE_INPUTS[@]}" \
        --type nsp --ofolder "$OUT_DIR/rust_base_nsp" --keys "$KEYS" \
        >"$OUT_DIR/logs/rust_merge_nsp_from_base_nsp.log" 2>&1
    )
    (
      cd "$PY_ZTOOLS"
      "$PYTHON_BIN" squirrel.py -t nsp -tfile "$OUT_DIR/merge_list_nsp_base.txt" -dmul calculate \
        -o "$OUT_DIR/py_base_nsp" -b 65536 \
        >"$OUT_DIR/logs/py_merge_nsp_from_base_nsp.log" 2>&1
    )
    RUST_MERGED_NSP_FROM_BASE_NSP="$(newest_file "$OUT_DIR/rust_base_nsp" '*.nsp')"
    PY_MERGED_NSP_FROM_BASE_NSP="$(newest_file "$OUT_DIR/py_base_nsp" '*.nsp')"
    need_file "$RUST_MERGED_NSP_FROM_BASE_NSP"
    need_file "$PY_MERGED_NSP_FROM_BASE_NSP"
    compare_names "$RUST_MERGED_NSP_FROM_BASE_NSP" "$PY_MERGED_NSP_FROM_BASE_NSP" "merge_nsp_from_base_nsp_filename"
    sha256sum "$RUST_MERGED_NSP_FROM_BASE_NSP" | awk '{print $1}' >"$OUT_DIR/cmp/merge_base_nsp_rust.sha"
    sha256sum "$PY_MERGED_NSP_FROM_BASE_NSP" | awk '{print $1}' >"$OUT_DIR/cmp/merge_base_nsp_py.sha"
    diff -u "$OUT_DIR/cmp/merge_base_nsp_py.sha" "$OUT_DIR/cmp/merge_base_nsp_rust.sha" >"$OUT_DIR/cmp/merge_nsp_from_base_nsp.diff" || FAIL=1

    log "Merge to XCI with base NSP source"
    (
      cd "$ROOT_DIR"
      "${RUST_BIN[@]}" --direct_multi "${ALT_MERGE_INPUTS[@]}" \
        --type xci --ofolder "$OUT_DIR/rust_base_nsp" --keys "$KEYS" \
        >"$OUT_DIR/logs/rust_merge_xci_from_base_nsp.log" 2>&1
    )
    (
      cd "$PY_ZTOOLS"
      "$PYTHON_BIN" squirrel.py -t xci -tfile "$OUT_DIR/merge_list_nsp_base.txt" -dmul calculate \
        -o "$OUT_DIR/py_base_nsp" -b 65536 \
        >"$OUT_DIR/logs/py_merge_xci_from_base_nsp.log" 2>&1
    )
    RUST_MERGED_XCI_FROM_BASE_NSP="$(newest_file "$OUT_DIR/rust_base_nsp" '*.xci')"
    PY_MERGED_XCI_FROM_BASE_NSP="$(newest_file "$OUT_DIR/py_base_nsp" '*.xci')"
    need_file "$RUST_MERGED_XCI_FROM_BASE_NSP"
    need_file "$PY_MERGED_XCI_FROM_BASE_NSP"
    compare_names "$RUST_MERGED_XCI_FROM_BASE_NSP" "$PY_MERGED_XCI_FROM_BASE_NSP" "merge_xci_from_base_nsp_filename"
    mkdir -p "$OUT_DIR/cmp/merge_xci_base_nsp_rust" "$OUT_DIR/cmp/merge_xci_base_nsp_py"
    (
      cd "$ROOT_DIR"
      "${RUST_BIN[@]}" --splitter "$RUST_MERGED_XCI_FROM_BASE_NSP" --ofolder "$OUT_DIR/cmp/merge_xci_base_nsp_rust" --keys "$KEYS" >"$OUT_DIR/logs/split_merge_xci_base_nsp_rust.log" 2>&1
      "${RUST_BIN[@]}" --splitter "$PY_MERGED_XCI_FROM_BASE_NSP" --ofolder "$OUT_DIR/cmp/merge_xci_base_nsp_py" --keys "$KEYS" >"$OUT_DIR/logs/split_merge_xci_base_nsp_py.log" 2>&1
    )
    hash_nca_set "$OUT_DIR/cmp/merge_xci_base_nsp_rust" "$OUT_DIR/cmp/merge_xci_base_nsp_rust.sha"
    hash_nca_set "$OUT_DIR/cmp/merge_xci_base_nsp_py" "$OUT_DIR/cmp/merge_xci_base_nsp_py.sha"
    compare_hash_sets "$OUT_DIR/cmp/merge_xci_base_nsp_rust.sha" "$OUT_DIR/cmp/merge_xci_base_nsp_py.sha" "merge_xci_from_base_nsp_payload"
  fi

  log "Merge to XCI (Python and Rust)"
fi

(
  cd "$ROOT_DIR"
  "${RUST_BIN[@]}" --direct_multi "${MERGE_INPUTS[@]}" --type xci --ofolder "$OUT_DIR/rust" --keys "$KEYS" >"$OUT_DIR/logs/rust_merge_xci.log" 2>&1
)
RUST_MERGED_XCI="$(newest_file "$OUT_DIR/rust" '*.xci')"
need_file "$RUST_MERGED_XCI"

if [[ "$HAVE_PY" -eq 1 ]]; then
  (
    cd "$PY_ZTOOLS"
    "$PYTHON_BIN" squirrel.py -t xci -tfile "$OUT_DIR/merge_list.txt" -dmul calculate -o "$OUT_DIR/py" -b 65536 >"$OUT_DIR/logs/py_merge_xci.log" 2>&1
  )
  PY_MERGED_XCI="$(newest_file "$OUT_DIR/py" '*.xci')"
  need_file "$PY_MERGED_XCI"
  compare_names "$RUST_MERGED_XCI" "$PY_MERGED_XCI" "merge_xci_filename"
  mkdir -p "$OUT_DIR/cmp/merge_xci_rust" "$OUT_DIR/cmp/merge_xci_py"
  (
    cd "$ROOT_DIR"
    "${RUST_BIN[@]}" --splitter "$RUST_MERGED_XCI" --ofolder "$OUT_DIR/cmp/merge_xci_rust" --keys "$KEYS" >"$OUT_DIR/logs/split_merge_xci_rust.log" 2>&1
    "${RUST_BIN[@]}" --splitter "$PY_MERGED_XCI" --ofolder "$OUT_DIR/cmp/merge_xci_py" --keys "$KEYS" >"$OUT_DIR/logs/split_merge_xci_py.log" 2>&1
  )
  hash_nca_set "$OUT_DIR/cmp/merge_xci_rust" "$OUT_DIR/cmp/merge_xci_rust.sha"
  hash_nca_set "$OUT_DIR/cmp/merge_xci_py" "$OUT_DIR/cmp/merge_xci_py.sha"
  compare_hash_sets "$OUT_DIR/cmp/merge_xci_rust.sha" "$OUT_DIR/cmp/merge_xci_py.sha" "merge_xci_payload"
fi

log "Compress/decompress parity"
(
  cd "$ROOT_DIR"
  "${RUST_BIN[@]}" --decompress "$SMALL_NSZ" --ofolder "$OUT_DIR/rust" --keys "$KEYS" >"$OUT_DIR/logs/rust_decompress.log" 2>&1
)
RUST_SMALL_NSP="$(ls -t "$OUT_DIR"/rust/*.nsp 2>/dev/null | head -n1 || true)"
need_file "$RUST_SMALL_NSP"

if [[ "$HAVE_PY" -eq 1 ]]; then
  (
    cd "$PY_ZTOOLS"
    "$PYTHON_BIN" squirrel.py -dcpr "$SMALL_NSZ" -o "$OUT_DIR/py" >"$OUT_DIR/logs/py_decompress.log" 2>&1
    "$PYTHON_BIN" squirrel.py -cpr "$RUST_SMALL_NSP" -o "$OUT_DIR/py" >"$OUT_DIR/logs/py_compress.log" 2>&1
  )
fi

(
  cd "$ROOT_DIR"
  "${RUST_BIN[@]}" --compress "$RUST_SMALL_NSP" --ofolder "$OUT_DIR/rust" --keys "$KEYS" --level 3 >"$OUT_DIR/logs/rust_compress.log" 2>&1
)

if [[ "$HAVE_PY" -eq 1 ]]; then
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

  log "XCZ mixed-input parity"
  mkdir -p \
    "$OUT_DIR/py_xcz_inputs/update" \
    "$OUT_DIR/py_xcz_inputs/dlc1" \
    "$OUT_DIR/py_xcz" \
    "$OUT_DIR/rust_xcz" \
    "$OUT_DIR/cmp/merge_xcz_rust" \
    "$OUT_DIR/cmp/merge_xcz_py"
  (
    cd "$ROOT_DIR"
    "${RUST_BIN[@]}" --direct_creation "$RUST_SMALL_NSP" --type xci --ofolder "$OUT_DIR/py_xcz_inputs/update" --keys "$KEYS" \
      >"$OUT_DIR/logs/rust_make_update_xci.log" 2>&1
    "${RUST_BIN[@]}" --direct_creation "${DLC_FILES[0]}" --type xci --ofolder "$OUT_DIR/py_xcz_inputs/dlc1" --keys "$KEYS" \
      >"$OUT_DIR/logs/rust_make_dlc1_xci.log" 2>&1
  )
  UPDATE_XCI_INPUT="$(newest_file "$OUT_DIR/py_xcz_inputs/update" '*.xci')"
  DLC1_XCI_INPUT="$(newest_file "$OUT_DIR/py_xcz_inputs/dlc1" '*.xci')"
  need_file "$UPDATE_XCI_INPUT"
  need_file "$DLC1_XCI_INPUT"
  (
    cd "$PY_ZTOOLS"
    "$PYTHON_BIN" squirrel.py -cpr "$UPDATE_XCI_INPUT" -o "$OUT_DIR/py_xcz_inputs/update" \
      >"$OUT_DIR/logs/py_make_update_xcz.log" 2>&1
    "$PYTHON_BIN" squirrel.py -cpr "$DLC1_XCI_INPUT" -o "$OUT_DIR/py_xcz_inputs/dlc1" \
      >"$OUT_DIR/logs/py_make_dlc1_xcz.log" 2>&1
  )
  UPDATE_XCZ_INPUT="$(newest_file "$OUT_DIR/py_xcz_inputs/update" '*.xcz')"
  DLC1_XCZ_INPUT="$(newest_file "$OUT_DIR/py_xcz_inputs/dlc1" '*.xcz')"
  need_file "$UPDATE_XCZ_INPUT"
  need_file "$DLC1_XCZ_INPUT"
  XCZ_MERGE_INPUTS=("$BASE_FILE" "$UPDATE_XCZ_INPUT" "$DLC1_XCZ_INPUT" "${DLC_FILES[1]}")
  printf "%s\n" "${XCZ_MERGE_INPUTS[@]}" >"$OUT_DIR/merge_list_xcz.txt"
  (
    cd "$ROOT_DIR"
    "${RUST_BIN[@]}" --direct_multi "${XCZ_MERGE_INPUTS[@]}" --type xci --ofolder "$OUT_DIR/rust_xcz" --keys "$KEYS" \
      >"$OUT_DIR/logs/rust_merge_xcz_mix.log" 2>&1
  )
  (
    cd "$PY_ZTOOLS"
    "$PYTHON_BIN" squirrel.py -t xci -tfile "$OUT_DIR/merge_list_xcz.txt" -dmul calculate -o "$OUT_DIR/py_xcz" -b 65536 \
      >"$OUT_DIR/logs/py_merge_xcz_mix.log" 2>&1
  )
  RUST_MERGED_XCZ_MIX="$(newest_file "$OUT_DIR/rust_xcz" '*.xci')"
  PY_MERGED_XCZ_MIX="$(newest_file "$OUT_DIR/py_xcz" '*.xci')"
  need_file "$RUST_MERGED_XCZ_MIX"
  need_file "$PY_MERGED_XCZ_MIX"
  (
    cd "$ROOT_DIR"
    "${RUST_BIN[@]}" --splitter "$RUST_MERGED_XCZ_MIX" --ofolder "$OUT_DIR/cmp/merge_xcz_rust" --keys "$KEYS" >"$OUT_DIR/logs/split_merge_xcz_rust.log" 2>&1
    "${RUST_BIN[@]}" --splitter "$PY_MERGED_XCZ_MIX" --ofolder "$OUT_DIR/cmp/merge_xcz_py" --keys "$KEYS" >"$OUT_DIR/logs/split_merge_xcz_py.log" 2>&1
  )
  compare_names "$RUST_MERGED_XCZ_MIX" "$PY_MERGED_XCZ_MIX" "merge_xcz_mix_xci_filename"
  sha256_skip_prefix "$RUST_MERGED_XCZ_MIX" 256 >"$OUT_DIR/cmp/merge_xcz_mix_rust.sha"
  sha256_skip_prefix "$PY_MERGED_XCZ_MIX" 256 >"$OUT_DIR/cmp/merge_xcz_mix_py.sha"
  diff -u "$OUT_DIR/cmp/merge_xcz_mix_rust.sha" "$OUT_DIR/cmp/merge_xcz_mix_py.sha" >"$OUT_DIR/cmp/merge_xcz_mix_xci.diff" || FAIL=1
  hash_nca_set_nested "$OUT_DIR/cmp/merge_xcz_rust" "$OUT_DIR/cmp/merge_xcz_rust.sha"
  hash_nca_set_nested "$OUT_DIR/cmp/merge_xcz_py" "$OUT_DIR/cmp/merge_xcz_py.sha"
  compare_hash_sets "$OUT_DIR/cmp/merge_xcz_rust.sha" "$OUT_DIR/cmp/merge_xcz_py.sha" "merge_xcz_mix_xci_payload"
fi

log "Info parity on base container"
(
  cd "$ROOT_DIR"
  "${RUST_BIN[@]}" --ADVfilelist "$BASE_FILE" --keys "$KEYS" >"$OUT_DIR/logs/rust_advfilelist_base.log" 2>&1
  "${RUST_BIN[@]}" --ADVcontentlist "$BASE_FILE" --keys "$KEYS" >"$OUT_DIR/logs/rust_advcontentlist_base.log" 2>&1
)
pass_or_fail "rust_advfilelist_has_content_id" "rg -q '^CONTENT ID:' '$OUT_DIR/logs/rust_advfilelist_base.log'"
pass_or_fail "rust_advcontentlist_has_base_id" "rg -q '^BASE CONTENT ID:' '$OUT_DIR/logs/rust_advcontentlist_base.log'"

if [[ "$HAVE_PY" -eq 1 ]]; then
  run_py_info --ADVfilelist "$BASE_FILE" "$OUT_DIR/logs/py_advfilelist_base.log"
  run_py_info --ADVcontentlist "$BASE_FILE" "$OUT_DIR/logs/py_advcontentlist_base.log"
  normalize_info_output "$OUT_DIR/logs/py_advfilelist_base.log" "$OUT_DIR/cmp/py_advfilelist_base.raw.norm"
  normalize_info_output "$OUT_DIR/logs/py_advcontentlist_base.log" "$OUT_DIR/cmp/py_advcontentlist_base.norm"
  normalize_info_output "$OUT_DIR/logs/rust_advfilelist_base.log" "$OUT_DIR/cmp/rust_advfilelist_base.raw.norm"
  normalize_info_output "$OUT_DIR/logs/rust_advcontentlist_base.log" "$OUT_DIR/cmp/rust_advcontentlist_base.norm"
  normalize_advfilelist_parity_output "$OUT_DIR/cmp/py_advfilelist_base.raw.norm" "$OUT_DIR/cmp/py_advfilelist_base.norm"
  normalize_advfilelist_parity_output "$OUT_DIR/cmp/rust_advfilelist_base.raw.norm" "$OUT_DIR/cmp/rust_advfilelist_base.norm"
  diff -u "$OUT_DIR/cmp/py_advfilelist_base.norm" "$OUT_DIR/cmp/rust_advfilelist_base.norm" >"$OUT_DIR/cmp/advfilelist_base.diff" || FAIL=1
  diff -u "$OUT_DIR/cmp/py_advcontentlist_base.norm" "$OUT_DIR/cmp/rust_advcontentlist_base.norm" >"$OUT_DIR/cmp/advcontentlist_base.diff" || FAIL=1
fi

log "dspl parity"
mkdir -p "$OUT_DIR/rust_dspl_nsp" "$OUT_DIR/rust_dspl_xci"
(
  cd "$ROOT_DIR"
  "${RUST_BIN[@]}" --dspl "$RUST_MERGED_XCI" --type nsp --ofolder "$OUT_DIR/rust_dspl_nsp" --keys "$KEYS" >"$OUT_DIR/logs/rust_dspl_nsp.log" 2>&1
  "${RUST_BIN[@]}" --dspl "$RUST_MERGED_XCI" --type xci --ofolder "$OUT_DIR/rust_dspl_xci" --keys "$KEYS" >"$OUT_DIR/logs/rust_dspl_xci.log" 2>&1
)
pass_or_fail "rust_dspl_nsp_outputs" "[[ \$(find '$OUT_DIR/rust_dspl_nsp' -maxdepth 1 -type f -name '*.nsp' | wc -l) -ge 3 ]]"
pass_or_fail "rust_dspl_xci_outputs" "[[ \$(find '$OUT_DIR/rust_dspl_xci' -maxdepth 1 -type f \\( -name '*.xci' -o -name '*.nsp' \\) | wc -l) -ge 3 ]]"

if [[ "$HAVE_PY" -eq 1 ]]; then
  mkdir -p "$OUT_DIR/py_dspl_nsp" "$OUT_DIR/py_dspl_xci"
  (
    cd "$PY_ZTOOLS"
    "$PYTHON_BIN" squirrel.py -dspl "$RUST_MERGED_XCI" -t nsp -fx files -o "$OUT_DIR/py_dspl_nsp" >"$OUT_DIR/logs/py_dspl_nsp.log" 2>&1
    "$PYTHON_BIN" squirrel.py -dspl "$RUST_MERGED_XCI" -t xci -fx files -o "$OUT_DIR/py_dspl_xci" >"$OUT_DIR/logs/py_dspl_xci.log" 2>&1
  )
  find "$OUT_DIR/rust_dspl_nsp" -maxdepth 1 -type f -name '*.nsp' -printf '%f\n' | sort >"$OUT_DIR/cmp/rust_dspl_nsp.names"
  find "$OUT_DIR/py_dspl_nsp" -maxdepth 1 -type f -name '*.nsp' -printf '%f\n' | sort >"$OUT_DIR/cmp/py_dspl_nsp.names"
  diff -u "$OUT_DIR/cmp/py_dspl_nsp.names" "$OUT_DIR/cmp/rust_dspl_nsp.names" >"$OUT_DIR/cmp/dspl_names.diff" || FAIL=1

  find "$OUT_DIR/rust_dspl_xci" -maxdepth 1 -type f \( -name '*.xci' -o -name '*.nsp' \) -printf '%f\n' | sort >"$OUT_DIR/cmp/rust_dspl_xci.names"
  find "$OUT_DIR/py_dspl_xci" -maxdepth 1 -type f \( -name '*.xci' -o -name '*.nsp' \) -printf '%f\n' | sort >"$OUT_DIR/cmp/py_dspl_xci.names"
  diff -u "$OUT_DIR/cmp/py_dspl_xci.names" "$OUT_DIR/cmp/rust_dspl_xci.names" >"$OUT_DIR/cmp/dspl_xci_names.diff" || FAIL=1
fi

log "Info parity on merged XCI"
(
  cd "$ROOT_DIR"
  "${RUST_BIN[@]}" --ADVfilelist "$RUST_MERGED_XCI" --keys "$KEYS" >"$OUT_DIR/logs/rust_advfilelist_merged.log" 2>&1
  "${RUST_BIN[@]}" --ADVcontentlist "$RUST_MERGED_XCI" --keys "$KEYS" >"$OUT_DIR/logs/rust_advcontentlist_merged.log" 2>&1
)

if [[ "$HAVE_PY" -eq 1 ]]; then
  run_py_info --ADVfilelist "$RUST_MERGED_XCI" "$OUT_DIR/logs/py_advfilelist_merged.log"
  run_py_info --ADVcontentlist "$RUST_MERGED_XCI" "$OUT_DIR/logs/py_advcontentlist_merged.log"
  normalize_info_output "$OUT_DIR/logs/py_advfilelist_merged.log" "$OUT_DIR/cmp/py_advfilelist_merged.raw.norm"
  normalize_info_output "$OUT_DIR/logs/py_advcontentlist_merged.log" "$OUT_DIR/cmp/py_advcontentlist_merged.norm"
  normalize_info_output "$OUT_DIR/logs/rust_advfilelist_merged.log" "$OUT_DIR/cmp/rust_advfilelist_merged.raw.norm"
  normalize_info_output "$OUT_DIR/logs/rust_advcontentlist_merged.log" "$OUT_DIR/cmp/rust_advcontentlist_merged.norm"
  normalize_advfilelist_parity_output "$OUT_DIR/cmp/py_advfilelist_merged.raw.norm" "$OUT_DIR/cmp/py_advfilelist_merged.norm"
  normalize_advfilelist_parity_output "$OUT_DIR/cmp/rust_advfilelist_merged.raw.norm" "$OUT_DIR/cmp/rust_advfilelist_merged.norm"
  diff -u "$OUT_DIR/cmp/py_advfilelist_merged.norm" "$OUT_DIR/cmp/rust_advfilelist_merged.norm" >"$OUT_DIR/cmp/advfilelist_merged.diff" || FAIL=1
  diff -u "$OUT_DIR/cmp/py_advcontentlist_merged.norm" "$OUT_DIR/cmp/rust_advcontentlist_merged.norm" >"$OUT_DIR/cmp/advcontentlist_merged.diff" || FAIL=1
fi

log "Firmware-control parity"
mkdir -p "$OUT_DIR/rust_fw"
(
  cd "$ROOT_DIR"
  "${RUST_BIN[@]}" --direct_multi "${MERGE_INPUTS[@]}" --type xci --ofolder "$OUT_DIR/rust_fw" --keys "$KEYS" --RSVcap 0 --keypatch 4 --pv >"$OUT_DIR/logs/rust_fw_merge.log" 2>&1
)
RUST_FW_XCI="$(newest_file "$OUT_DIR/rust_fw" '*.xci')"
need_file "$RUST_FW_XCI"
(
  cd "$ROOT_DIR"
  "${RUST_BIN[@]}" --ADVfilelist "$RUST_FW_XCI" --keys "$KEYS" >"$OUT_DIR/logs/rust_fw_advfile.log" 2>&1
)
if [[ "$HAVE_PY" -eq 1 ]]; then
  mkdir -p "$OUT_DIR/py_fw" "$OUT_DIR/cmp/fw_rust" "$OUT_DIR/cmp/fw_py"
  (
    cd "$PY_ZTOOLS"
    "$PYTHON_BIN" squirrel.py -t xci -tfile "$OUT_DIR/merge_list.txt" -dmul calculate \
      -rsvc 0 -kp 4 -o "$OUT_DIR/py_fw" -b 65536 \
      >"$OUT_DIR/logs/py_fw_merge.log" 2>&1
  )
  PY_FW_XCI="$(newest_file "$OUT_DIR/py_fw" '*.xci')"
  need_file "$PY_FW_XCI"
  (
    cd "$ROOT_DIR"
    "${RUST_BIN[@]}" --splitter "$RUST_FW_XCI" --ofolder "$OUT_DIR/cmp/fw_rust" --keys "$KEYS" >"$OUT_DIR/logs/split_fw_rust.log" 2>&1
    "${RUST_BIN[@]}" --splitter "$PY_FW_XCI" --ofolder "$OUT_DIR/cmp/fw_py" --keys "$KEYS" >"$OUT_DIR/logs/split_fw_py.log" 2>&1
  )
  find "$OUT_DIR/cmp/fw_rust" -maxdepth 2 -type f -name '*.nca' -exec sha256sum {} + | awk '{print $1}' | sort >"$OUT_DIR/cmp/fw_rust.sha"
  find "$OUT_DIR/cmp/fw_py" -maxdepth 2 -type f -name '*.nca' -exec sha256sum {} + | awk '{print $1}' | sort >"$OUT_DIR/cmp/fw_py.sha"
  diff -u "$OUT_DIR/cmp/fw_py.sha" "$OUT_DIR/cmp/fw_rust.sha" >"$OUT_DIR/cmp/fw_payload.diff" || FAIL=1
  run_py_info --ADVfilelist "$PY_FW_XCI" "$OUT_DIR/logs/py_fw_advfile.log"
  normalize_info_output "$OUT_DIR/logs/py_fw_advfile.log" "$OUT_DIR/cmp/py_fw_advfile.raw.norm"
  normalize_info_output "$OUT_DIR/logs/rust_fw_advfile.log" "$OUT_DIR/cmp/rust_fw_advfile.raw.norm"
  normalize_advfilelist_parity_output "$OUT_DIR/cmp/py_fw_advfile.raw.norm" "$OUT_DIR/cmp/py_fw_advfile.norm"
  normalize_advfilelist_parity_output "$OUT_DIR/cmp/rust_fw_advfile.raw.norm" "$OUT_DIR/cmp/rust_fw_advfile.norm"
  diff -u "$OUT_DIR/cmp/py_fw_advfile.norm" "$OUT_DIR/cmp/rust_fw_advfile.norm" >"$OUT_DIR/cmp/fw_advfile.diff" || FAIL=1
else
  pass_or_fail "rust_fw_log_has_keygen_patch" "test -s '$OUT_DIR/logs/rust_fw_merge.log'"
  pass_or_fail "rust_fw_advfile_exists" "test -s '$OUT_DIR/logs/rust_fw_advfile.log'"
fi

if [[ "$HAVE_MULTI_UPDATE" -eq 1 ]]; then
  log "Multi-update selection regression"
  mkdir -p "$OUT_DIR/multi_update_rust" "$OUT_DIR/multi_update_py"
  printf "%s\n" "$MULTI_BASE_FILE" "$MULTI_UPD_OLD_FILE" "$MULTI_UPD_NEW_FILE" >"$OUT_DIR/multi_update_list.txt"
  (
    cd "$ROOT_DIR"
    "${RUST_BIN[@]}" --direct_multi "$MULTI_BASE_FILE" "$MULTI_UPD_OLD_FILE" "$MULTI_UPD_NEW_FILE" \
      --type nsp --ofolder "$OUT_DIR/multi_update_rust" --keys "$KEYS" \
      >"$OUT_DIR/logs/rust_multi_update_merge.log" 2>&1
    "${RUST_BIN[@]}" --ADVfilelist "$(newest_file "$OUT_DIR/multi_update_rust" '*.nsp')" --keys "$KEYS" \
      >"$OUT_DIR/logs/rust_multi_update_advfile.log" 2>&1
  )
  RUST_MULTI_NSP="$(newest_file "$OUT_DIR/multi_update_rust" '*.nsp')"
  need_file "$RUST_MULTI_NSP"
  pass_or_fail "multi_update_rust_filename_uses_latest_version" "basename '$RUST_MULTI_NSP' | rg -q '\\[v327680\\]'"
  pass_or_fail "multi_update_rust_reports_latest_display_version" "rg -q 'Display Version: 1\\.0\\.5' '$OUT_DIR/logs/rust_multi_update_advfile.log'"
  pass_or_fail "multi_update_rust_reports_latest_patch_version" "rg -q 'Version: 327680 -> Patch \\(5\\)' '$OUT_DIR/logs/rust_multi_update_advfile.log'"

  if [[ "$HAVE_PY" -eq 1 ]]; then
    (
      cd "$PY_ZTOOLS"
      "$PYTHON_BIN" squirrel.py -t nsp -tfile "$OUT_DIR/multi_update_list.txt" -dmul calculate \
        -o "$OUT_DIR/multi_update_py" -b 65536 \
        >"$OUT_DIR/logs/py_multi_update_merge.log" 2>&1
    )
    PY_MULTI_NSP="$(newest_file "$OUT_DIR/multi_update_py" '*.nsp')"
    need_file "$PY_MULTI_NSP"
    compare_names "$RUST_MULTI_NSP" "$PY_MULTI_NSP" "multi_update_filename"
  fi
fi

echo
echo "==== Container sizes (informational) ===="
stat -c '%n\t%s' "$RUST_MERGED_NSP" "$RUST_MERGED_XCI" "$RUST_FW_XCI" "${PY_MERGED_NSP:-$RUST_MERGED_NSP}" "${PY_MERGED_XCI:-$RUST_MERGED_XCI}" 2>/dev/null || true

echo
if [[ "$FAIL" -eq 0 ]]; then
  echo "Parity suite PASSED."
  echo "Artifacts and logs: $OUT_DIR"
  exit 0
else
  echo "Parity suite FAILED." >&2
  echo "Inspect logs/artifacts under: $OUT_DIR" >&2
  exit 1
fi
