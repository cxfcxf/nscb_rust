# nscb_rust

Rust implementation of core Nintendo Switch content workflows inspired by NSC_Builder `squirrel.py`.

Implemented operations:
- Merge (`--direct_multi`, `-d`)
- Split (`--splitter`)
- Create/Repack NSP from folder (`--create` + `--ifolder`)
- Convert NSP/XCI (`--direct_creation`, `-c`)
- Compress NSP/XCI (`--compress`, `-z`)
- Decompress NSZ/XCZ/NCZ (`--decompress`)

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
  - Trigger pattern: `v*` (example: `v0.1.0`)
- Workflow file:
  - `.github/workflows/release-windows.yml`

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

### 4) Convert NSP -> XCI

```bash
target/release/nscb \
  --direct_creation "game.nsp" \
  --type xci \
  --keys /path/to/prod.keys \
  -o /path/to/output
```

### 5) Convert XCI -> NSP

```bash
target/release/nscb \
  --direct_creation "game.xci" \
  --type nsp \
  --keys /path/to/prod.keys \
  -o /path/to/output
```

### 6) Compress NSP -> NSZ (or XCI -> XCZ)

```bash
target/release/nscb \
  --compress "game.nsp" \
  --level 3 \
  --keys /path/to/prod.keys \
  -o /path/to/output
```

### 7) Decompress NSZ -> NSP (or XCZ -> XCI, NCZ -> NCA)

```bash
target/release/nscb \
  --decompress "game.nsz" \
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

Common env vars:

- `TEST_DIR`: folder containing test inputs and `prod.keys`
- `BASE_FILE`: base input file
- `UPD_FILE`: update input file
- `MERGE_EXTRA`: newline-separated extra merge inputs (typically DLC files)
- `SMALL_NSZ`: small NSZ file for compress/decompress checks
- `OUT_DIR`: output artifacts/logs folder
- `PY_REPO`: local NSC_BUILDER clone path

For exact mixed-input merge parity (`direct_multi -t nsp` quirks), set:

```bash
NSCB_PY_ZTOOLS=/tmp/NSC_BUILDER_cfx/py/ztools
NSCB_PYTHON=/tmp/NSC_BUILDER_cfx/.venv/bin/python
```

Example (`E:\dumps\game_set` on WSL as `/mnt/e/dumps/game_set`):

```bash
BASE_FILE="$(find /mnt/e/dumps/game_set -maxdepth 1 -type f -iname '*.nsz' | rg '\[APP\]' | head -n1)"
UPD_FILE="$(find /mnt/e/dumps/game_set -maxdepth 1 -type f -iname '*.nsz' | rg '\[UPD\]' | head -n1)"
SMALL_NSZ="$(find /mnt/e/dumps/game_set -maxdepth 1 -type f -iname '*.nsz' | rg '\[DLC' | head -n1)"
MERGE_EXTRA="$(find /mnt/e/dumps/game_set -maxdepth 1 -type f -iname '*.nsz' | rg '\[DLC' | sort)"
TEST_DIR=/mnt/e/dumps/game_set \
OUT_DIR=/tmp/parity_example \
PY_REPO=/tmp/NSC_BUILDER_cfx \
NSCB_PY_ZTOOLS=/tmp/NSC_BUILDER_cfx/py/ztools \
NSCB_PYTHON=/tmp/NSC_BUILDER_cfx/.venv/bin/python \
BASE_FILE="$BASE_FILE" \
UPD_FILE="$UPD_FILE" \
SMALL_NSZ="$SMALL_NSZ" \
MERGE_EXTRA="$MERGE_EXTRA" \
./run_parity_exact.sh
```
