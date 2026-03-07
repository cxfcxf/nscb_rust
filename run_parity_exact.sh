#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="${TEST_DIR:-/mnt/e/test}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/.qa_suite/exact_script}"
KEYS="${KEYS:-$TEST_DIR/prod.keys}"
PY_REPO="${PY_REPO:-$ROOT_DIR/.qa_suite/reference/NSC_BUILDER}"
PY_ZTOOLS="${PY_ZTOOLS:-$PY_REPO/py/ztools}"
PYTHON_BIN="${PYTHON_BIN:-$PY_REPO/.venv/bin/python}"
RUST_BIN=("$ROOT_DIR/target/debug/nscb")
FAIL=0

BASE_FILE="${BASE_FILE:-$(find "$TEST_DIR" -maxdepth 1 -type f \( -name '*.xci' -o -name '*.nsp' \) ! -name '[[]UPD[]]*' ! -name '[[]DLC[]]*' | sort | head -n1)}"
UPD_FILE="${UPD_FILE:-$(find "$TEST_DIR" -maxdepth 1 -type f \( -name '[[]UPD[]]*.nsz' -o -name '[[]UPD[]]*.nsp' \) | sort | head -n1)}"
SMALL_NSZ="${SMALL_NSZ:-$UPD_FILE}"
mapfile -t DLC_FILES < <(find "$TEST_DIR" -maxdepth 1 -type f -name '[[]DLC[]]*.nsp' | sort)

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
RUST_MERGED_NSP="$(find "$OUT_DIR/rust" -maxdepth 1 -type f -name '*.nsp' | head -n1)"
need_file "$RUST_MERGED_NSP"

if [[ "$HAVE_PY" -eq 1 ]]; then
  log "Merge to NSP (Python)"
  (
    cd "$PY_ZTOOLS"
    "$PYTHON_BIN" squirrel.py -t nsp -tfile "$OUT_DIR/merge_list.txt" -dmul calculate \
      -o "$OUT_DIR/py" -b 65536 \
      >"$OUT_DIR/logs/py_merge_nsp.log" 2>&1
  )
  PY_MERGED_NSP="$(find "$OUT_DIR/py" -maxdepth 1 -type f -name '*.nsp' | head -n1)"
  need_file "$PY_MERGED_NSP"
  compare_names "$RUST_MERGED_NSP" "$PY_MERGED_NSP" "merge_nsp_filename"

  log "Merge NSP parity (payload compare via split/hash)"
  mkdir -p "$OUT_DIR/cmp/merge_split_rust" "$OUT_DIR/cmp/merge_split_py"
  (
    cd "$ROOT_DIR"
    "${RUST_BIN[@]}" --splitter "$RUST_MERGED_NSP" --ofolder "$OUT_DIR/cmp/merge_split_rust" --keys "$KEYS" >"$OUT_DIR/logs/merge_split_rust.log" 2>&1
    "${RUST_BIN[@]}" --splitter "$PY_MERGED_NSP" --ofolder "$OUT_DIR/cmp/merge_split_py" --keys "$KEYS" >"$OUT_DIR/logs/merge_split_py.log" 2>&1
  )
  hash_nca_set "$OUT_DIR/cmp/merge_split_rust" "$OUT_DIR/cmp/merge_rust.sha"
  hash_nca_set "$OUT_DIR/cmp/merge_split_py" "$OUT_DIR/cmp/merge_py.sha"
  compare_hash_sets "$OUT_DIR/cmp/merge_rust.sha" "$OUT_DIR/cmp/merge_py.sha" "merge_nsp_payload"

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

  log "Merge to XCI (Python and Rust)"
fi

(
  cd "$ROOT_DIR"
  "${RUST_BIN[@]}" --direct_multi "${MERGE_INPUTS[@]}" --type xci --ofolder "$OUT_DIR/rust" --keys "$KEYS" >"$OUT_DIR/logs/rust_merge_xci.log" 2>&1
)
RUST_MERGED_XCI="$(find "$OUT_DIR/rust" -maxdepth 1 -type f -name '*.xci' | head -n1)"
need_file "$RUST_MERGED_XCI"

if [[ "$HAVE_PY" -eq 1 ]]; then
  (
    cd "$PY_ZTOOLS"
    "$PYTHON_BIN" squirrel.py -t xci -tfile "$OUT_DIR/merge_list.txt" -dmul calculate -o "$OUT_DIR/py" -b 65536 >"$OUT_DIR/logs/py_merge_xci.log" 2>&1
  )
  PY_MERGED_XCI="$(find "$OUT_DIR/py" -maxdepth 1 -type f -name '*.xci' | head -n1)"
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
  normalize_info_output "$OUT_DIR/logs/py_advfilelist_base.log" "$OUT_DIR/cmp/py_advfilelist_base.norm"
  normalize_info_output "$OUT_DIR/logs/py_advcontentlist_base.log" "$OUT_DIR/cmp/py_advcontentlist_base.norm"
  normalize_info_output "$OUT_DIR/logs/rust_advfilelist_base.log" "$OUT_DIR/cmp/rust_advfilelist_base.norm"
  normalize_info_output "$OUT_DIR/logs/rust_advcontentlist_base.log" "$OUT_DIR/cmp/rust_advcontentlist_base.norm"
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
  normalize_info_output "$OUT_DIR/logs/py_advfilelist_merged.log" "$OUT_DIR/cmp/py_advfilelist_merged.norm"
  normalize_info_output "$OUT_DIR/logs/py_advcontentlist_merged.log" "$OUT_DIR/cmp/py_advcontentlist_merged.norm"
  normalize_info_output "$OUT_DIR/logs/rust_advfilelist_merged.log" "$OUT_DIR/cmp/rust_advfilelist_merged.norm"
  normalize_info_output "$OUT_DIR/logs/rust_advcontentlist_merged.log" "$OUT_DIR/cmp/rust_advcontentlist_merged.norm"
  diff -u "$OUT_DIR/cmp/py_advfilelist_merged.norm" "$OUT_DIR/cmp/rust_advfilelist_merged.norm" >"$OUT_DIR/cmp/advfilelist_merged.diff" || FAIL=1
  diff -u "$OUT_DIR/cmp/py_advcontentlist_merged.norm" "$OUT_DIR/cmp/rust_advcontentlist_merged.norm" >"$OUT_DIR/cmp/advcontentlist_merged.diff" || FAIL=1
fi

log "Firmware-control parity"
mkdir -p "$OUT_DIR/rust_fw"
(
  cd "$ROOT_DIR"
  "${RUST_BIN[@]}" --direct_multi "${MERGE_INPUTS[@]}" --type xci --ofolder "$OUT_DIR/rust_fw" --keys "$KEYS" --RSVcap 0 --keypatch 4 --pv >"$OUT_DIR/logs/rust_fw_merge.log" 2>&1
)
RUST_FW_XCI="$(find "$OUT_DIR/rust_fw" -maxdepth 1 -type f -name '*.xci' | head -n1)"
need_file "$RUST_FW_XCI"
(
  cd "$ROOT_DIR"
  "${RUST_BIN[@]}" --ADVfilelist "$RUST_FW_XCI" --keys "$KEYS" >"$OUT_DIR/logs/rust_fw_advfile.log" 2>&1
)
pass_or_fail "rust_fw_log_has_keygen_patch" "rg -q 'keygen .* -> 4' '$OUT_DIR/logs/rust_fw_merge.log'"
pass_or_fail "rust_fw_content_has_keygen4" "rg -q 'Encryption \\(keygeneration\\): 4' '$OUT_DIR/logs/rust_fw_advfile.log'"

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
