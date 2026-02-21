use clap::Parser;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use crate::error::Result;
use crate::formats::nsp::Nsp;
use crate::formats::types::{ContentType, TitleType};
use crate::formats::xci::Xci;
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
        let filtered_files: Vec<&str> = files
            .iter()
            .map(|s| s.as_str())
            .filter(|p| !is_ignored_merge_input_path(p))
            .collect();
        if filtered_files.is_empty() {
            return Err(crate::error::NscbError::InvalidData(
                "No valid input files after filtering metadata sidecar entries".to_string(),
            ));
        }
        let file_refs: Vec<&str> = filtered_files.clone();
        let merge_name = build_merge_filename_metadata(&file_refs, &args.output_type, &ks)
            .unwrap_or_else(|| build_merge_filename(&file_refs, &args.output_type));
        let nsp_direct_multi_python_mode = args.output_type.eq_ignore_ascii_case("nsp")
            && file_refs.iter().any(|p| {
                let lower = p.to_ascii_lowercase();
                lower.ends_with(".xci") || lower.ends_with(".xcz")
            });
        let output = make_output_path(
            filtered_files.first().copied().unwrap_or("merged"),
            &args.ofolder,
            &merge_name,
        );
        return crate::ops::merge::merge(
            &file_refs,
            &output,
            &ks,
            args.nodelta,
            &args.output_type,
            nsp_direct_multi_python_mode,
        );
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
    let file_name = Path::new(default_name)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let safe_file_name = sanitize_output_filename(&file_name);

    if let Some(dir) = ofolder {
        Path::new(dir)
            .join(safe_file_name.as_str())
            .to_string_lossy()
            .into()
    } else {
        // If the generated output name contains invalid filesystem characters,
        // keep it in the current directory with a safe basename.
        safe_file_name
    }
}

fn sanitize_output_filename(name: &str) -> String {
    let (stem, ext) = if let Some((s, e)) = name.rsplit_once('.') {
        (s.to_string(), format!(".{}", e))
    } else {
        (name.to_string(), String::new())
    };
    let mut out = stem;
    // Mirror squirrel.py cleanup used for generated output names.
    out = Regex::new(r"[\/\\:\*\?]+")
        .unwrap()
        .replace_all(&out, "")
        .to_string();
    out = Regex::new(r#"[™©®`~\^´ªº¢#£€¥$ƒ±¬½¼♡«»•²‰œæÆ³☆<>|]"#)
        .unwrap()
        .replace_all(&out, "")
        .to_string();

    let translits = [
        ("Ⅰ", "I"),
        ("Ⅱ", "II"),
        ("Ⅲ", "III"),
        ("Ⅳ", "IV"),
        ("Ⅴ", "V"),
        ("Ⅵ", "VI"),
        ("Ⅶ", "VII"),
        ("Ⅷ", "VIII"),
        ("Ⅸ", "IX"),
        ("Ⅹ", "X"),
        ("Ⅺ", "XI"),
        ("Ⅻ", "XII"),
        ("Ⅼ", "L"),
        ("Ⅽ", "C"),
        ("Ⅾ", "D"),
        ("Ⅿ", "M"),
        ("—", "-"),
        ("√", "Root"),
        ("à", "a"),
        ("â", "a"),
        ("á", "a"),
        ("@", "a"),
        ("ä", "a"),
        ("å", "a"),
        ("À", "A"),
        ("Â", "A"),
        ("Á", "A"),
        ("Ä", "A"),
        ("Å", "A"),
        ("è", "e"),
        ("ê", "e"),
        ("é", "e"),
        ("ë", "e"),
        ("È", "E"),
        ("Ê", "E"),
        ("É", "E"),
        ("Ë", "E"),
        ("ì", "i"),
        ("î", "i"),
        ("í", "i"),
        ("ï", "i"),
        ("Ì", "I"),
        ("Î", "I"),
        ("Í", "I"),
        ("Ï", "I"),
        ("ò", "o"),
        ("ô", "o"),
        ("ó", "o"),
        ("ö", "o"),
        ("ø", "o"),
        ("Ò", "O"),
        ("Ô", "O"),
        ("Ó", "O"),
        ("Ö", "O"),
        ("Ø", "O"),
        ("ù", "u"),
        ("û", "u"),
        ("ú", "u"),
        ("ü", "u"),
        ("Ù", "U"),
        ("Û", "U"),
        ("Ú", "U"),
        ("Ü", "U"),
        ("’", "'"),
        ("“", "\""),
        ("”", "\""),
    ];
    for (from, to) in translits {
        out = out.replace(from, to);
    }

    out = Regex::new(r" {3,}")
        .unwrap()
        .replace_all(&out, " ")
        .to_string();
    out = out.replace("( ", "(");
    out = out.replace(" )", ")");
    out = out.replace("[ ", "[");
    out = out.replace(" ]", "]");
    out = out.replace("[ (", "[(");
    out = out.replace(") ]", ")]");
    out = out.replace("[]", "");
    out = out.replace("()", "");
    out = out.replace("\" ", "\"");
    out = out.replace(" \"", "\"");
    out = out.replace(" !", "!");
    out = out.replace(" ?", "?");
    out = out.replace("  ", " ");
    out = out.replace("  ", " ");
    out = out.replace('"', "");
    out = out.replace(")", ") ");
    out = out.replace("]", "] ");
    out = out.replace("[ (", "[(");
    out = out.replace(") ]", ")]");
    out = out.replace("  ", " ");
    out = out.trim_end().to_string();

    if out.is_empty() {
        if ext.is_empty() {
            "merged.nsp".to_string()
        } else {
            format!("merged{}", ext)
        }
    } else {
        format!("{}{}", out, ext)
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
    let mut considered_count = 0usize;

    // Regex to extract title ID from filenames like [0100633007D48000] or -0100633007D48000-
    let tid_re = Regex::new(r"[\[-]([0-9A-Fa-f]{16})[\]-]").unwrap();
    // Regex to extract version: [v458752] in brackets, or --v\d+- in dash format
    let ver_bracket_re = Regex::new(r"\[v(\d+)\]").unwrap();
    let ver_dash_re = Regex::new(r"--v(\d+)-").unwrap();
    // Regex to detect content type tags
    let upd_re = Regex::new(r"(?i)\[UPD\]").unwrap();
    let dlc_re = Regex::new(r"(?i)\[DLC\]").unwrap();

    for path_str in input_paths {
        if is_ignored_merge_input_path(path_str) {
            continue;
        }
        considered_count += 1;
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

        // Determine content type from filename tags or title ID pattern.
        // Fallback to title-id suffix when explicit tags are missing:
        // - ...800 => update
        // - ...000 => base/game
        // - otherwise => DLC
        let has_update_tid = title_ids.iter().any(|tid| tid.ends_with("800"));
        let has_base_tid = title_ids.iter().any(|tid| tid.ends_with("000"));
        let has_dlc_tid = title_ids
            .iter()
            .any(|tid| !tid.ends_with("800") && !tid.ends_with("000"));

        let is_update = upd_re.is_match(&filename) || has_update_tid;
        let is_dlc = dlc_re.is_match(&filename) || (!is_update && has_dlc_tid && !has_base_tid);
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
        format!("{}F", considered_count)
    } else {
        parts.join("+")
    };

    format!(
        "{} [{}] [v{}] ({}).{}",
        name, tid, ver, summary, output_type
    )
}

fn is_ignored_merge_input_path(path_str: &str) -> bool {
    let name = Path::new(path_str)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    name.starts_with("._") || name.eq_ignore_ascii_case(".ds_store")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MergeKind {
    Base,
    Update,
    Dlc,
}

#[derive(Debug, Clone, Copy)]
struct MergeTitleRecord {
    title_id: u64,
    version: u32,
    kind: MergeKind,
}

fn kind_from_title_type(title_type: Option<TitleType>, title_id: u64) -> MergeKind {
    match title_type {
        Some(TitleType::Application) => MergeKind::Base,
        Some(TitleType::Patch) => MergeKind::Update,
        Some(TitleType::AddOnContent) => MergeKind::Dlc,
        _ => match title_id & 0xFFF {
            0x000 => MergeKind::Base,
            0x800 => MergeKind::Update,
            _ => MergeKind::Dlc,
        },
    }
}

fn build_merge_filename_metadata(
    input_paths: &[&str],
    output_type: &str,
    ks: &KeyStore,
) -> Option<String> {
    let (records, latest_version, title_name) = collect_title_records(input_paths, ks);
    if records.is_empty() {
        return None;
    }

    let mut base_count = 0u32;
    let mut update_count = 0u32;
    let mut dlc_count = 0u32;
    let mut base_tid: Option<u64> = None;
    let mut update_tid: Option<u64> = None;

    for rec in records.values() {
        match rec.kind {
            MergeKind::Base => {
                base_count += 1;
                if base_tid.is_none() {
                    base_tid = Some(rec.title_id);
                }
            }
            MergeKind::Update => {
                update_count += 1;
                if update_tid.is_none() {
                    update_tid = Some(rec.title_id);
                }
            }
            MergeKind::Dlc => dlc_count += 1,
        }
    }

    let title_id = base_tid.or_else(|| {
        update_tid.map(|u| {
            let mut s = format!("{:016X}", u);
            let len = s.len();
            s.replace_range(len - 3.., "000");
            u64::from_str_radix(&s, 16).unwrap_or(u)
        })
    });
    let tid = format!("{:016X}", title_id.unwrap_or(0));
    let name = title_name
        .filter(|s| !s.trim().is_empty() && s != "DLC")
        .unwrap_or_else(|| infer_game_name_from_path(input_paths.first().copied().unwrap_or("merged")));
    let ver = latest_version.unwrap_or(0);

    let mut ccount = String::new();
    if base_count > 0 {
        ccount.push_str(&format!("{}G", base_count));
    }
    if update_count > 0 {
        if !ccount.is_empty() {
            ccount.push('+');
        }
        ccount.push_str(&format!("{}U", update_count));
    }
    if dlc_count > 0 {
        if !ccount.is_empty() {
            ccount.push('+');
        }
        ccount.push_str(&format!("{}D", dlc_count));
    }
    let ccount = if ccount == "1G" || ccount == "1U" || ccount == "1D" || ccount.is_empty() {
        String::new()
    } else {
        format!(" ({})", ccount)
    };

    Some(format!(
        "{} [{}] [v{}]{}.{}",
        name, tid, ver, ccount, output_type
    ))
}

fn collect_title_records(
    input_paths: &[&str],
    ks: &KeyStore,
) -> (HashMap<u64, MergeTitleRecord>, Option<u32>, Option<String>) {
    let mut temp_files: Vec<tempfile::NamedTempFile> = Vec::new();
    let mut effective_paths: Vec<String> = Vec::new();

    for path_str in input_paths {
        if is_ignored_merge_input_path(path_str) {
            continue;
        }
        let ext = Path::new(path_str)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        match ext.as_str() {
            "nsz" | "xcz" => {
                if let Ok(tmp) = tempfile::NamedTempFile::new() {
                    let tmp_path = tmp.path().to_string_lossy().to_string();
                    if crate::ops::decompress::decompress(path_str, &tmp_path).is_ok() {
                        effective_paths.push(tmp_path);
                        temp_files.push(tmp);
                    } else {
                        effective_paths.push((*path_str).to_string());
                    }
                } else {
                    effective_paths.push((*path_str).to_string());
                }
            }
            _ => effective_paths.push((*path_str).to_string()),
        }
    }

    let mut by_title: HashMap<u64, MergeTitleRecord> = HashMap::new();
    let mut latest_version: Option<u32> = None;
    let mut title_name: Option<String> = None;

    for path_str in &effective_paths {
        let ext = Path::new(path_str)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        match ext.as_str() {
            "nsp" => {
                let _ =
                    collect_title_records_from_nsp(path_str, ks, &mut by_title, &mut latest_version, &mut title_name);
            }
            "xci" => {
                let _ =
                    collect_title_records_from_xci(path_str, ks, &mut by_title, &mut latest_version, &mut title_name);
            }
            _ => {
                // Decompressed temp files may not have extension.
                if collect_title_records_from_nsp(path_str, ks, &mut by_title, &mut latest_version, &mut title_name)
                    .is_err()
                {
                    let _ = collect_title_records_from_xci(
                        path_str,
                        ks,
                        &mut by_title,
                        &mut latest_version,
                        &mut title_name,
                    );
                }
            }
        }
    }

    if by_title.len() < input_paths.len() {
        add_filename_fallback_records(input_paths, &mut by_title, &mut latest_version);
    }

    drop(temp_files);
    (by_title, latest_version, title_name)
}

fn collect_title_records_from_nsp(
    path: &str,
    ks: &KeyStore,
    out: &mut HashMap<u64, MergeTitleRecord>,
    latest_version: &mut Option<u32>,
    title_name: &mut Option<String>,
) -> std::result::Result<(), ()> {
    let mut file = BufReader::new(File::open(path).map_err(|_| ())?);
    let nsp = Nsp::parse(&mut file).map_err(|_| ())?;

    let mut found_any = false;
    for meta in nsp.cnmt_nca_entries(&mut file, ks) {
        if let Some(entry) = nsp.pfs0.find(&meta.filename) {
            let abs_offset = nsp.file_abs_offset(entry);
            if let Some(cnmt) = crate::ops::split::parse_cnmt_from_meta_nca(&mut file, abs_offset, ks) {
                found_any = true;
                upsert_record(
                    out,
                    MergeTitleRecord {
                        title_id: cnmt.title_id,
                        version: cnmt.version,
                        kind: kind_from_title_type(cnmt.title_type_enum(), cnmt.title_id),
                    },
                );
                if latest_version.is_none_or(|v| cnmt.version > v) {
                    *latest_version = Some(cnmt.version);
                }
            }
        }
    }

    // Title lookup path similar to squirrel.get_title(): read CONTROL NCA -> NACP title.
    if title_name.is_none() {
        for entry in nsp.nca_entries() {
            if let Ok(info) =
                crate::formats::nca::parse_nca_info(&mut file, nsp.file_abs_offset(entry), entry.size, &entry.name, ks)
            {
                if info.content_type == Some(ContentType::Control) {
                    let abs_offset = nsp.file_abs_offset(entry);
                    if let Some(name) =
                        crate::ops::split::parse_nacp_title_from_control_nca(&mut file, abs_offset, ks)
                    {
                        *title_name = Some(name);
                        break;
                    }
                }
            }
        }
    }

    if found_any { Ok(()) } else { Err(()) }
}

fn collect_title_records_from_xci(
    path: &str,
    ks: &KeyStore,
    out: &mut HashMap<u64, MergeTitleRecord>,
    latest_version: &mut Option<u32>,
    title_name: &mut Option<String>,
) -> std::result::Result<(), ()> {
    let mut file = BufReader::new(File::open(path).map_err(|_| ())?);
    let xci = Xci::parse(&mut file).map_err(|_| ())?;
    let secure_entries = xci.secure_nca_entries(&mut file).map_err(|_| ())?;

    let mut found_any = false;
    for entry in &secure_entries {
        if let Ok(info) =
            crate::formats::nca::parse_nca_info(&mut file, entry.abs_offset, entry.size, &entry.name, ks)
        {
            if info.content_type == Some(ContentType::Meta) {
                if let Some(cnmt) =
                    crate::ops::split::parse_cnmt_from_meta_nca(&mut file, entry.abs_offset, ks)
                {
                    found_any = true;
                    upsert_record(
                        out,
                        MergeTitleRecord {
                            title_id: cnmt.title_id,
                            version: cnmt.version,
                            kind: kind_from_title_type(cnmt.title_type_enum(), cnmt.title_id),
                        },
                    );
                    if latest_version.is_none_or(|v| cnmt.version > v) {
                        *latest_version = Some(cnmt.version);
                    }
                } else {
                    found_any = true;
                    upsert_record(
                        out,
                        MergeTitleRecord {
                            title_id: info.title_id,
                            version: 0,
                            kind: kind_from_title_type(None, info.title_id),
                        },
                    );
                }
            } else if info.content_type == Some(ContentType::Control) && title_name.is_none() {
                if let Some(name) =
                    crate::ops::split::parse_nacp_title_from_control_nca(&mut file, entry.abs_offset, ks)
                {
                    *title_name = Some(name);
                }
            }
        }
    }

    if found_any {
        return Ok(());
    }

    // Last fallback for unusual XCI layouts where Meta content-type detection fails:
    // parse explicit *.cnmt.nca entries by filename.
    for entry in &secure_entries {
        if entry.name.to_ascii_lowercase().ends_with(".cnmt.nca") {
            if let Some(cnmt) =
                crate::ops::split::parse_cnmt_from_meta_nca(&mut file, entry.abs_offset, ks)
            {
                found_any = true;
                upsert_record(
                    out,
                    MergeTitleRecord {
                        title_id: cnmt.title_id,
                        version: cnmt.version,
                        kind: kind_from_title_type(cnmt.title_type_enum(), cnmt.title_id),
                    },
                );
                if latest_version.is_none_or(|v| cnmt.version > v) {
                    *latest_version = Some(cnmt.version);
                }
            }
        }
    }

    if found_any { Ok(()) } else { Err(()) }
}

fn upsert_record(map: &mut HashMap<u64, MergeTitleRecord>, rec: MergeTitleRecord) {
    match map.get(&rec.title_id) {
        Some(cur) if cur.version >= rec.version => {}
        _ => {
            map.insert(rec.title_id, rec);
        }
    }
}

fn add_filename_fallback_records(
    input_paths: &[&str],
    out: &mut HashMap<u64, MergeTitleRecord>,
    latest_version: &mut Option<u32>,
) {
    let tid_re = Regex::new(r"[\[-]([0-9A-Fa-f]{16})[\]-]").unwrap();
    let ver_bracket_re = Regex::new(r"\[v(\d+)\]").unwrap();
    let ver_dash_re = Regex::new(r"--v(\d+)-").unwrap();
    let num_bracket_re = Regex::new(r"\[(\d+)\]").unwrap();
    let upd_re = Regex::new(r"(?i)\[UPD\]").unwrap();
    let dlc_re = Regex::new(r"(?i)\[DLC\]").unwrap();

    for path_str in input_paths {
        let filename = Path::new(path_str)
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let tid = tid_re
            .captures_iter(&filename)
            .next()
            .and_then(|c| u64::from_str_radix(&c[1], 16).ok());
        let Some(title_id) = tid else {
            continue;
        };

        let has_update_tid = (title_id & 0xFFF) == 0x800;
        let has_base_tid = (title_id & 0xFFF) == 0x000;
        let kind = if upd_re.is_match(&filename) || has_update_tid {
            MergeKind::Update
        } else if dlc_re.is_match(&filename) || !has_base_tid {
            MergeKind::Dlc
        } else {
            MergeKind::Base
        };

        let mut version = ver_bracket_re
            .captures(&filename)
            .or_else(|| ver_dash_re.captures(&filename))
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().parse::<u32>().ok())
            .unwrap_or(0);
        if version == 0 {
            for cap in num_bracket_re.captures_iter(&filename) {
                if let Ok(v) = cap[1].parse::<u32>() {
                    if v > version {
                        version = v;
                    }
                }
            }
        }

        upsert_record(
            out,
            MergeTitleRecord {
                title_id,
                version,
                kind,
            },
        );
        if latest_version.is_none_or(|v| version > v) {
            *latest_version = Some(version);
        }
    }
}

fn infer_game_name_from_path(path_str: &str) -> String {
    let filename = Path::new(path_str)
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    if let Some(bracket_pos) = filename.find('[') {
        let n = filename[..bracket_pos].trim();
        if !n.is_empty() {
            return n.to_string();
        }
    }
    if let Some(dash_pos) = filename.find('-') {
        let n = filename[..dash_pos].trim();
        if !n.is_empty() {
            return n.to_string();
        }
    }
    let n = filename.trim();
    if n.is_empty() {
        "merged".to_string()
    } else {
        n.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{build_merge_filename, sanitize_output_filename};

    #[test]
    fn merge_filename_counts_dlc_without_dlc_tag() {
        let mut inputs = vec![
            "SUPER ROBOT WARS Y [010063301BD50000][v0].nsp".to_string(),
            "SUPER ROBOT WARS Y [010063301BD50800][v524288].nsp".to_string(),
        ];
        for i in 1..=7 {
            inputs.push(format!(
                "SUPER ROBOT WARS Y Pack {} [010063301BD5{:04X}][v0].nsp",
                i, i
            ));
        }
        let input_refs: Vec<&str> = inputs.iter().map(|s| s.as_str()).collect();
        let out = build_merge_filename(&input_refs, "xci");
        assert!(out.contains("(1G+1U+7D).xci"), "actual output: {}", out);
    }

    #[test]
    fn merge_filename_counts_update_without_upd_tag() {
        let inputs = vec![
            "Game [0100123412345000][v0].nsp",
            "Game [0100123412345800][v65536].nsp",
        ];
        let out = build_merge_filename(&inputs, "nsp");
        assert!(out.contains("(1G+1U).nsp"), "actual output: {}", out);
    }

    #[test]
    fn sanitize_filename_removes_windows_unsafe_chars_like_squirrel() {
        let out = sanitize_output_filename("Hollow Knight: Silksong [010013C00E930000].xci");
        assert!(
            !out.contains(':'),
            "sanitized output must not contain ':'; got {}",
            out
        );
        assert_eq!(
            out,
            "Hollow Knight Silksong [010013C00E930000].xci".to_string()
        );
    }
}
