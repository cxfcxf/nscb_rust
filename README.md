# nscb_rust

Rust implementation of core Nintendo Switch content workflows inspired by NSC_Builder `squirrel.py`.

Implemented operations:
- Merge (`--direct_multi`, `-d`)
- Split (`--splitter`)
- Split to repacked files (`--dspl`)
- Create/Repack NSP from folder (`--create` + `--ifolder`)
- Convert NSP/XCI (`--direct_creation`, `-c`)
- Compress NSP/XCI (`--compress`, `-z`)
- Decompress NSZ/XCZ/NCZ (`--decompress`)
- Content viewer (`--ADVcontentlist`)
- Metadata/file list (`--ADVfilelist`)
- Firmware controls on merge (`--RSVcap`, `--keypatch`, `--pv`)

## Requirements

- Rust toolchain (stable)
- `prod.keys` (or pass `--keys <path>`)

## Build

```bash
cargo build --release
```

Binary path:

```bash
target/release/nscb
```

## Windows EXE

### Download from GitHub Releases

- On tag push, GitHub Actions builds and publishes:
  - `nscb_rust.exe`
  - `nscb_rust-linux-amd64`
  - `nscb_rust-macos-arm64`
  - Trigger pattern: `v*` (example: `v0.1.0`)
- Workflow file:
  - `.github/workflows/release.yml`

### Local cross-build from Linux (optional)

```bash
rustup target add x86_64-pc-windows-gnu
sudo apt-get update && sudo apt-get install -y mingw-w64
cargo build --release --target x86_64-pc-windows-gnu
```

Output:

```bash
target/x86_64-pc-windows-gnu/release/nscb.exe
```

## Quick Help

```bash
target/release/nscb --help
```

## Common Options

- `--keys <path>`: path to `prod.keys`
- `-o, --ofolder <dir>`: output folder
- `-t, --type <nsp|xci>`: target type for convert/merge output mode
- `--level <1-22>`: compression level (default: `3`)
- `-n, --nodelta`: exclude delta NCAs during merge

## Usage

### 1) Merge base/update/DLC

```bash
target/release/nscb \
  -d "base.nsp" "update.nsz" "dlc.nsp" \
  --keys /path/to/prod.keys \
  -o /path/to/output
```

### 2) Split by title ID (CNMT-aware naming)

```bash
target/release/nscb \
  --splitter "merged.nsp_or_xci" \
  --keys /path/to/prod.keys \
  -o /path/to/split
```

Expected split output:
- Creates one folder per title group (base/update/DLC), not `.nsp` files.
- Folder names are title-aware, for example:
  - `Hollow Knight [0100633007D48000]`
  - `Hollow Knight [0100633007D48800][v458752][UPD]`
- Each folder contains extracted title content files, primarily `.nca`/`.ncz`.
- Tickets/certs are not guaranteed in split output; `--splitter` is designed for content grouping.

### 3) Create/Repack NSP from a split folder

```bash
target/release/nscb \
  --create "/path/to/repacked.nsp" \
  --ifolder "/path/to/split/Game Name [0100...000]" \
  --keys /path/to/prod.keys
```

Expected create behavior:
- Reads top-level files from `--ifolder`.
- Rebuilds a single `.nsp` with deterministic packing order.
- Typical workflow:
  - Split merged file with `--splitter`
  - Repack one split folder with `--create`

### 4) Split to per-title NSP/XCI files

```bash
target/release/nscb \
  --dspl "merged.xci" \
  --type nsp \
  --keys /path/to/prod.keys \
  -o /path/to/output
```

### 5) View detailed container contents

```bash
target/release/nscb \
  --ADVcontentlist "game.nsp_or_xci" \
  --keys /path/to/prod.keys
```

### 6) View title metadata summary

```bash
target/release/nscb \
  --ADVfilelist "game.nsp_or_xci" \
  --keys /path/to/prod.keys
```

### 7) Convert NSP -> XCI

```bash
target/release/nscb \
  --direct_creation "game.nsp" \
  --type xci \
  --keys /path/to/prod.keys \
  -o /path/to/output
```

### 8) Convert XCI -> NSP

```bash
target/release/nscb \
  --direct_creation "game.xci" \
  --type nsp \
  --keys /path/to/prod.keys \
  -o /path/to/output
```

### 9) Compress NSP -> NSZ (or XCI -> XCZ)

```bash
target/release/nscb \
  --compress "game.nsp" \
  --level 3 \
  --keys /path/to/prod.keys \
  -o /path/to/output
```

### 10) Decompress NSZ -> NSP (or XCZ -> XCI, NCZ -> NCA)

```bash
target/release/nscb \
  --decompress "game.nsz" \
  --keys /path/to/prod.keys \
  -o /path/to/output
```

### 11) Merge with firmware caps

```bash
target/release/nscb \
  -d "base.xci" "update.nsz" "dlc1.nsp" "dlc2.nsp" \
  --type xci \
  --RSVcap 0 \
  --keypatch 4 \
  --pv \
  --keys /path/to/prod.keys \
  -o /path/to/output
```

## Notes

- Progress bars are implemented for merge/decompress/convert operations, and also for compress/split.
- Split uses title-aware grouping and writes separate base/update/DLC folders.
- For large files, always use an output folder (`-o`) to avoid overwriting source content.
- If `--keys` is not set, the app also checks common default key locations.

## Parity Testing

Use the included parity runner to compare Rust outputs against NSC_BUILDER Python behavior:

```bash
./run_parity_exact.sh
```

`run_parity_exact.sh` is the single canonical regression entrypoint. It covers:
- merge parity (`nsp` and `xci`)
- split parity
- create parity
- compress/decompress parity
- XCZ mixed-input merge parity
- mixed `XCI base + NSP update -> NSP` regression
- `ADVcontentlist` output parity
- `ADVfilelist` output parity
- `dspl` filename parity
- firmware-control regression
- multi-update selection regression (`v1.0.4` + `v1.0.5` -> keep `v1.0.5`)

The Rust binary never delegates to `squirrel.py`. The Python reference is only used by the parity harness for comparison.

### Python Reference Setup

The parity runner expects a local NSC_BUILDER checkout plus a Python virtualenv:

```bash
mkdir -p .qa_suite/reference
git clone https://github.com/cxfcxf/NSC_BUILDER .qa_suite/reference/NSC_BUILDER
python3 -m venv .qa_suite/reference/NSC_BUILDER/.venv
.qa_suite/reference/NSC_BUILDER/.venv/bin/pip install --upgrade pip setuptools wheel
.qa_suite/reference/NSC_BUILDER/.venv/bin/pip install \
  pycryptodome \
  tqdm \
  zstandard \
  eel \
  bottle \
  bottle-websocket \
  pywebview \
  urllib3 \
  beautifulsoup4 \
  requests \
  pillow \
  chardet \
  pykakasi \
  googletrans==4.0.0rc1
```

Modules that were required in practice to boot `squirrel.py` and run the parity suite:

- `pycryptodome`
- `tqdm`
- `zstandard`
- `eel`
- `bottle`
- `bottle-websocket`
- `pywebview`
- `urllib3`
- `beautifulsoup4`
- `requests`
- `pillow`
- `chardet`
- `pykakasi`
- `googletrans==4.0.0rc1`

Expected layout:

```bash
$PWD/.qa_suite/reference/NSC_BUILDER
├── .venv/
└── py/ztools/
```

If you keep the Python reference tree there, `run_parity_exact.sh` works without extra env vars.

Common env vars:

- `TEST_DIR`: folder containing test inputs and `prod.keys`
- `MULTI_UPDATE_DIR`: separate folder for multi-update selection fixtures
- `TF_DIR`: mixed `XCI base + NSP update` regression fixture folder
- `BASE_FILE`: base input file
- `UPD_FILE`: update input file
- `MULTI_BASE_FILE`: base file for the multi-update regression case
- `MULTI_UPD_OLD_FILE`: older update file for the multi-update regression case
- `MULTI_UPD_NEW_FILE`: newer update file for the multi-update regression case
- `SMALL_NSZ`: small NSZ file for compress/decompress checks
- `OUT_DIR`: output artifacts/logs folder
- `PY_REPO`: local NSC_BUILDER clone path
- `PY_ZTOOLS`: override `py/ztools` inside the Python reference tree
- `PYTHON_BIN`: override the Python interpreter used for parity runs

Current local fixture layout used by the parity script:

- `/mnt/e/test/prod.keys`
- `/mnt/e/test/uo`
  Original Unicorn Overlord parity set:
  base `.xci`, one update `.nsz`, two DLC `.nsp`
- `/mnt/e/test/op`
  Multi-update Octopath Traveler regression set:
  base `.nsp`, update `v1.0.4`, update `v1.0.5`
- `/mnt/e/test/tf`
  Telenet Fuku-Bukuro mixed-input regression set:
  base `.xci`, update `.nsp`

### Intentional Differences

The suite is parity-first, but these differences are intentional and documented:

- `ADVfilelist` line `Patchable to:` is not parity-gated for higher key generations.
  Rust uses the extended RSV floor table so firmware downgrade reporting stays consistent with actual merge behavior. The Python reference falls back incorrectly for higher keygens.
- Multi-update `--direct_multi` NSP merges with duplicate-named update tickets/certs are not forced to match Python bit-for-bit.
  Rust keeps the highest-version update cleanly. Python's NSP text-file merge path can append stale ticket/cert bytes from the older update while still advertising only the newer update in the header, producing a larger malformed-but-usable NSP. Rust intentionally does not reproduce that container bug.
- Mixed `XCI -> NSP` merges are not treated as Python-authoritative when the Python reference emits an invalid NSP.
  This affects both the Unicorn Overlord mixed-input parity case and the Telenet Fuku-Bukuro regression fixture. In those cases the harness verifies that Rust produces a valid merged NSP with the expected content, and only performs Python split/hash comparison if the Python output is itself readable.
- Raw compressed `.nsz` / `.xcz` bytes are not parity-gated.
  The suite enforces decompressed payload parity and filename parity instead.
- XCI files ignore the first `0x100` bytes for exact byte comparison.
  Python randomizes the XCI signature block on each run, and Rust intentionally mimics that behavior.

Compression note:
- decompressed payload parity is enforced
- compressed `.nsz` / `.xcz` byte streams are not required to match Python bit-for-bit

Example (`E:\dumps\game_set` on WSL as `/mnt/e/dumps/game_set`):

```bash
BASE_FILE="$(find /mnt/e/dumps/game_set -maxdepth 1 -type f -iname '*.nsz' | rg '\[APP\]' | head -n1)"
UPD_FILE="$(find /mnt/e/dumps/game_set -maxdepth 1 -type f -iname '*.nsz' | rg '\[UPD\]' | head -n1)"
SMALL_NSZ="$(find /mnt/e/dumps/game_set -maxdepth 1 -type f -iname '*.nsz' | rg '\[DLC' | head -n1)"
TEST_DIR=/mnt/e/dumps/game_set \
OUT_DIR=.qa_suite/parity_example \
PY_REPO=.qa_suite/reference/NSC_BUILDER \
BASE_FILE="$BASE_FILE" \
UPD_FILE="$UPD_FILE" \
SMALL_NSZ="$SMALL_NSZ" \
./run_parity_exact.sh
```

Example for the current local split fixture layout:

```bash
TEST_DIR=/mnt/e/test/uo \
MULTI_UPDATE_DIR=/mnt/e/test/op \
TF_DIR=/mnt/e/test/tf \
KEYS=/mnt/e/test/prod.keys \
PY_REPO=.qa_suite/reference/NSC_BUILDER \
PY_ZTOOLS=.qa_suite/reference/NSC_BUILDER/py/ztools \
PYTHON_BIN=.qa_suite/reference/NSC_BUILDER/.venv/bin/python \
./run_parity_exact.sh
```
