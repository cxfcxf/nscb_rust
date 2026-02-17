# nscb_rust

Rust implementation of core Nintendo Switch content workflows inspired by NSC_Builder `squirrel.py`.

Implemented operations:
- Merge (`--direct_multi`, `-d`)
- Split (`--splitter`)
- Convert NSP/XCI (`--direct_creation`, `-c`)
- Compress NSP/XCI (`--compress`, `-z`)
- Decompress NSZ/XCZ/NCZ (`--decompress`)
- XCI trim/super-trim/untrim (`--xci_trim`, `--xci_super_trim`, `--xci_untrim`)

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

Note:
- Split output format is currently `NSP` files (even when input is `XCI`).

Example output names:
- `Game Name [0100...000].nsp`
- `Game Name [0100...800][v458752][UPD].nsp`
- `Game Name [0100...xxx][v...][DLC].nsp`

### 3) Convert NSP -> XCI

```bash
target/release/nscb \
  --direct_creation "game.nsp" \
  --type xci \
  --keys /path/to/prod.keys \
  -o /path/to/output
```

### 4) Convert XCI -> NSP

```bash
target/release/nscb \
  --direct_creation "game.xci" \
  --type nsp \
  --keys /path/to/prod.keys \
  -o /path/to/output
```

### 5) Compress NSP -> NSZ (or XCI -> XCZ)

```bash
target/release/nscb \
  --compress "game.nsp" \
  --level 3 \
  --keys /path/to/prod.keys \
  -o /path/to/output
```

### 6) Decompress NSZ -> NSP (or XCZ -> XCI, NCZ -> NCA)

```bash
target/release/nscb \
  --decompress "game.nsz" \
  --keys /path/to/prod.keys \
  -o /path/to/output
```

### 7) Trim XCI

```bash
target/release/nscb \
  --xci_trim "game.xci" \
  --keys /path/to/prod.keys \
  -o /path/to/output
```

### 8) Super-trim XCI

```bash
target/release/nscb \
  --xci_super_trim "game.xci" \
  --keys /path/to/prod.keys \
  -o /path/to/output
```

### 9) Untrim XCI (pad back to card size)

```bash
target/release/nscb \
  --xci_untrim "game.xci" \
  --keys /path/to/prod.keys \
  -o /path/to/output
```

## Notes

- Progress bars are implemented for merge/decompress/convert/trim operations, and also for compress/split.
- XCI split uses title-aware grouping and can produce separate base/update NSP outputs.
- For large files, always use an output folder (`-o`) to avoid overwriting source content.
- If `--keys` is not set, the app also checks common default key locations.
