use clap::Parser;
use std::path::Path;

use crate::error::Result;
use crate::keys::KeyStore;

use regex::Regex;

#[derive(Parser, Debug)]
#[command(name = "nscb", version, about = "Nintendo Switch Content Builder")]
pub struct Args {
    // === Operations ===
    /// Merge base+update+DLC into one NSP/XCI
    #[arg(long = "direct_multi", short = 'd', num_args = 1..)]
    pub direct_multi: Option<Vec<String>>,

    /// Split multi-title file into separate title folders with NCA files
    #[arg(long = "splitter", num_args = 1)]
    pub splitter: Option<String>,

    /// Create/repack NSP from an input folder
    #[arg(long = "create", num_args = 1)]
    pub create: Option<String>,

    /// Input folder for --create
    #[arg(long = "ifolder")]
    pub ifolder: Option<String>,

    /// Convert NSP↔XCI
    #[arg(long = "direct_creation", short = 'c', num_args = 1)]
    pub direct_creation: Option<String>,

    /// Compress NSP→NSZ or XCI→XCZ
    #[arg(long = "compress", short = 'z', num_args = 1)]
    pub compress: Option<String>,

    /// Decompress NSZ→NSP, XCZ→XCI, or NCZ→NCA
    #[arg(long = "decompress", num_args = 1)]
    pub decompress: Option<String>,

    // === Options ===
    /// Output format: nsp or xci
    #[arg(long = "type", short = 't', default_value = "nsp")]
    pub output_type: String,

    /// Output folder
    #[arg(long = "ofolder", short = 'o')]
    pub ofolder: Option<String>,

    /// Path to prod.keys
    #[arg(long = "keys")]
    pub keys: Option<String>,

    /// Exclude delta fragment NCAs
    #[arg(long = "nodelta", short = 'n')]
    pub nodelta: bool,

    /// Compression level (1-22, default 3)
    #[arg(long = "level", default_value = "3")]
    pub level: i32,

    /// I/O buffer size in bytes
    #[arg(long = "buffer", short = 'b')]
    pub buffer: Option<usize>,
}

pub fn dispatch(args: Args) -> Result<()> {
    // Load keys (needed for most operations that parse NCA headers)
    let ks = KeyStore::from_default_locations(args.keys.as_deref())?;

    // Dispatch to the correct operation
    if let Some(files) = &args.direct_multi {
        let file_refs: Vec<&str> = files.iter().map(|s| s.as_str()).collect();
        let merge_name = build_merge_filename(&file_refs, &args.output_type);
        let output = make_output_path(
            files.first().map(|s| s.as_str()).unwrap_or("merged"),
            &args.ofolder,
            &merge_name,
        );
        return crate::ops::merge::merge(&file_refs, &output, &ks, args.nodelta, &args.output_type);
    }

    if let Some(path) = &args.splitter {
        let output_dir = args.ofolder.as_deref().unwrap_or("./split");
        return crate::ops::split::split(path, output_dir, &ks);
    }

    if let Some(output_path) = &args.create {
        let input_dir = args.ifolder.as_deref().ok_or_else(|| {
            crate::error::NscbError::InvalidData(
                "--create requires --ifolder <input_folder>".to_string(),
            )
        })?;
        return crate::ops::create::create_from_folder(input_dir, output_path, &ks);
    }

    if let Some(path) = &args.direct_creation {
        let output = make_output_path(path, &args.ofolder, &change_ext(path, &args.output_type));
        return crate::ops::convert::convert(path, &output, &args.output_type, &ks);
    }

    if let Some(path) = &args.compress {
        let output = make_output_path(path, &args.ofolder, &compress_ext(path));
        return crate::ops::compress::compress(path, &output, args.level, &ks);
    }

    if let Some(path) = &args.decompress {
        let output = make_output_path(path, &args.ofolder, &decompress_ext(path));
        return crate::ops::decompress::decompress(path, &output);
    }

    eprintln!("No operation specified. Use --help for usage.");
    Ok(())
}

/// Build output path: if ofolder is set, put the file there; otherwise use the derived name.
fn make_output_path(_input: &str, ofolder: &Option<String>, default_name: &str) -> String {
    if let Some(dir) = ofolder {
        let name = Path::new(default_name)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        Path::new(dir).join(name.as_ref()).to_string_lossy().into()
    } else {
        default_name.to_string()
    }
}

fn change_ext(path: &str, new_ext: &str) -> String {
    let p = Path::new(path);
    p.with_extension(new_ext).to_string_lossy().into()
}

fn compress_ext(path: &str) -> String {
    let p = Path::new(path);
    let ext = p.extension().unwrap_or_default().to_string_lossy();
    match ext.as_ref() {
        "nsp" => p.with_extension("nsz").to_string_lossy().into(),
        "xci" => p.with_extension("xcz").to_string_lossy().into(),
        "nca" => p.with_extension("ncz").to_string_lossy().into(),
        _ => format!("{}.compressed", path),
    }
}

fn decompress_ext(path: &str) -> String {
    let p = Path::new(path);
    let ext = p.extension().unwrap_or_default().to_string_lossy();
    match ext.as_ref() {
        "nsz" => p.with_extension("nsp").to_string_lossy().into(),
        "xcz" => p.with_extension("xci").to_string_lossy().into(),
        "ncz" => p.with_extension("nca").to_string_lossy().into(),
        _ => format!("{}.decompressed", path),
    }
}

/// Build a descriptive merge output filename from input file paths.
///
/// Parses input filenames to extract game name, title IDs, and versions.
/// Produces: `{GameName} [{BaseTitleID}] [{LatestVersion}] ({Summary}).{ext}`
///
/// Where Summary is like `1G+1U` or `1G+1U+2D`.
fn build_merge_filename(input_paths: &[&str], output_type: &str) -> String {
    let mut game_name: Option<String> = None;
    let mut base_title_id: Option<String> = None;
    let mut latest_version: Option<String> = None;
    let mut game_count = 0u32;
    let mut update_count = 0u32;
    let mut dlc_count = 0u32;

    // Regex to extract title ID from filenames like [0100633007D48000] or -0100633007D48000-
    let tid_re = Regex::new(r"[\[-]([0-9A-Fa-f]{16})[\]-]").unwrap();
    // Regex to extract version: [v458752] in brackets, or --v\d+- in dash format
    let ver_bracket_re = Regex::new(r"\[v(\d+)\]").unwrap();
    let ver_dash_re = Regex::new(r"--v(\d+)-").unwrap();
    // Regex to detect content type tags
    let upd_re = Regex::new(r"(?i)\[UPD\]").unwrap();
    let dlc_re = Regex::new(r"(?i)\[DLC\]").unwrap();

    for path_str in input_paths {
        let filename = Path::new(path_str)
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        // Extract game name: everything before the first '[' or title ID pattern
        if game_name.is_none() {
            let name = if let Some(bracket_pos) = filename.find('[') {
                filename[..bracket_pos].trim()
            } else if let Some(dash_pos) = filename.find('-') {
                filename[..dash_pos].trim()
            } else {
                filename.trim()
            };
            if !name.is_empty() {
                game_name = Some(name.to_string());
            }
        }

        // Extract title IDs
        let title_ids: Vec<String> = tid_re
            .captures_iter(&filename)
            .map(|c| c[1].to_uppercase())
            .collect();

        // Determine content type from filename tags or title ID pattern
        let is_update = upd_re.is_match(&filename);
        let is_dlc = dlc_re.is_match(&filename);
        let is_base = !is_update && !is_dlc;

        // Title ID heuristic: base ends in 000, update ends in 800, DLC is between
        for tid in &title_ids {
            if tid.ends_with("000") && base_title_id.is_none() {
                base_title_id = Some(tid.clone());
            } else if tid.ends_with("800") && base_title_id.is_none() {
                // Derive base from update ID: replace last 3 chars with 000
                let mut base = tid.clone();
                let len = base.len();
                base.replace_range(len - 3.., "000");
                base_title_id = Some(base);
            }
        }

        // Extract version — prefer bracketed [v458752], fall back to --v0-
        let ver_cap = ver_bracket_re
            .captures(&filename)
            .or_else(|| ver_dash_re.captures(&filename));
        if let Some(cap) = ver_cap {
            let ver: u64 = cap[1].parse().unwrap_or(0);
            if let Some(ref cur) = latest_version {
                let cur_ver: u64 = cur.parse().unwrap_or(0);
                if ver > cur_ver {
                    latest_version = Some(cap[1].to_string());
                }
            } else {
                latest_version = Some(cap[1].to_string());
            }
        }

        // Count content types
        if is_update {
            update_count += 1;
        } else if is_dlc {
            dlc_count += 1;
        } else if is_base {
            game_count += 1;
        }
    }

    // Build the filename
    let name = game_name.unwrap_or_else(|| "merged".to_string());
    let tid = base_title_id.unwrap_or_else(|| "0000000000000000".to_string());
    let ver = latest_version.unwrap_or_else(|| "0".to_string());

    // Build summary like "1G+1U" or "1G+1U+2D"
    let mut parts = Vec::new();
    if game_count > 0 {
        parts.push(format!("{}G", game_count));
    }
    if update_count > 0 {
        parts.push(format!("{}U", update_count));
    }
    if dlc_count > 0 {
        parts.push(format!("{}D", dlc_count));
    }
    let summary = if parts.is_empty() {
        format!("{}F", input_paths.len())
    } else {
        parts.join("+")
    };

    format!(
        "{} [{}] [v{}] ({}).{}",
        name, tid, ver, summary, output_type
    )
}
