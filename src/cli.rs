use clap::Parser;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::formats::nsp::Nsp;
use crate::formats::types::{ContentType, TitleType};
use crate::formats::xci::Xci;
use crate::keys::KeyStore;
use crate::nutdb::{base_title_id, NutdbStore};

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

    /// Print full container content details
    #[arg(long = "ADVcontentlist", num_args = 1)]
    pub adv_contentlist: Option<String>,

    /// Print title metadata summary
    #[arg(long = "ADVfilelist", num_args = 1)]
    pub adv_filelist: Option<String>,

    /// Split multi-title file into repacked NSP/XCI files
    #[arg(long = "dspl", num_args = 1)]
    pub dspl: Option<String>,

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

    /// Rename a file or all supported files in a folder using package metadata and NUTDB
    #[arg(long = "renamef", num_args = 1)]
    pub renamef: Option<String>,

    /// Rename mode for --renamef: force, skip_corr_tid, skip_if_tid
    #[arg(long = "renmode")]
    pub renmode: Option<String>,

    /// Append language tag during --renamef
    #[arg(long = "addlangue")]
    pub addlangue: Option<String>,

    /// Omit version during --renamef: false, true, xci_no_v0
    #[arg(long = "noversion")]
    pub noversion: Option<String>,

    /// DLC naming mode for --renamef: false, true, tag
    #[arg(long = "dlcrname")]
    pub dlcrname: Option<String>,

    /// Refresh the local NUTDB cache using conditional HTTP when supported
    #[arg(long = "nutdb-refresh")]
    pub nutdb_refresh: bool,

    /// Look up a title ID in the local NUTDB cache
    #[arg(long = "nutdb-lookup", num_args = 1)]
    pub nutdb_lookup: Option<String>,

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

    /// Cap RequiredSystemVersion during merge
    #[arg(long = "RSVcap")]
    pub rsvcap: Option<u32>,

    /// Lower NCA key generation during merge
    #[arg(long = "keypatch", short = 'k')]
    pub keypatch: Option<u8>,

    /// Print before/after firmware info during merge
    #[arg(long = "pv")]
    pub print_version: bool,

    /// Compression level (1-22, default 3)
    #[arg(long = "level", default_value = "3")]
    pub level: i32,

    /// I/O buffer size in bytes
    #[arg(long = "buffer", short = 'b')]
    pub buffer: Option<usize>,

    /// Override the NUTDB source URL
    #[arg(long = "nutdb-url")]
    pub nutdb_url: Option<String>,

    /// Override the NUTDB cache directory
    #[arg(long = "nutdb-cache-dir")]
    pub nutdb_cache_dir: Option<String>,
}

pub fn dispatch(args: Args) -> Result<()> {
    let nutdb = NutdbStore::new(args.nutdb_cache_dir.as_deref(), args.nutdb_url.as_deref());

    if args.nutdb_refresh {
        let outcome = nutdb.refresh()?;
        println!(
            "NUTDB cache {} at {} ({} indexed titles)",
            outcome.status.as_str(),
            nutdb.cache_dir().display(),
            outcome.indexed_titles
        );
        return Ok(());
    }

    if let Some(title_id) = &args.nutdb_lookup {
        let index = nutdb.ensure_index()?;
        let base_id = base_title_id(title_id);
        if let Some(title) = index.lookup(title_id) {
            println!("title_id={}", title_id.trim().to_ascii_uppercase());
            println!("base_id={base_id}");
            println!(
                "display_name={}",
                index
                    .display_name_for(title_id)
                    .unwrap_or_else(|| "-".to_string())
            );
            println!("name={}", title.name.as_deref().unwrap_or("-"));
            println!("publisher={}", title.publisher.as_deref().unwrap_or("-"));
            println!(
                "languages={}",
                if title.languages.is_empty() {
                    "-".to_string()
                } else {
                    title.languages.join(",")
                }
            );
            println!(
                "version={}",
                title
                    .version
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".to_string())
            );
        } else if let Some(display_name) = index.display_name_for(title_id) {
            println!("title_id={}", title_id.trim().to_ascii_uppercase());
            println!("base_id={base_id}");
            println!("display_name={display_name}");
            println!("name=-");
            println!("publisher=-");
            println!("languages=-");
            println!("version=-");
        } else {
            return Err(crate::error::NscbError::InvalidData(format!(
                "No NUTDB entry found for title ID {}",
                title_id
            )));
        }
        return Ok(());
    }

    let mut key_store: Option<KeyStore> = None;

    if let Some(path) = &args.renamef {
        let ks = get_key_store(&mut key_store, args.keys.as_deref())?;
        let index = nutdb.ensure_index()?;
        let rename_options = RenameOptions::from_args(
            args.renmode.as_deref(),
            args.addlangue.as_deref(),
            args.noversion.as_deref(),
            args.dlcrname.as_deref(),
        );
        let renamed = rename_target(path, ks, &index, rename_options)?;
        println!("Renamed {} item(s)", renamed);
        return Ok(());
    }

    // Dispatch to the correct operation
    if let Some(files) = &args.direct_multi {
        let ks = get_key_store(&mut key_store, args.keys.as_deref())?;
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
        let merge_name = build_merge_filename_metadata(&file_refs, &args.output_type, ks, &nutdb)
            .unwrap_or_else(|| build_merge_filename(&file_refs, &args.output_type));
        let nsp_direct_multi_python_mode = args.output_type.eq_ignore_ascii_case("nsp");
        let output = make_output_path(
            filtered_files.first().copied().unwrap_or("merged"),
            &args.ofolder,
            &merge_name,
        );
        return crate::ops::merge::merge(
            &file_refs,
            &output,
            ks,
            args.nodelta,
            &args.output_type,
            nsp_direct_multi_python_mode,
            args.rsvcap,
            args.keypatch,
            args.print_version,
        );
    }

    if let Some(path) = &args.splitter {
        let ks = get_key_store(&mut key_store, args.keys.as_deref())?;
        let output_dir = args.ofolder.as_deref().unwrap_or("./split");
        return crate::ops::split::split(path, output_dir, ks);
    }

    if let Some(path) = &args.adv_contentlist {
        let ks = get_key_store(&mut key_store, args.keys.as_deref())?;
        return crate::ops::info::content_list(path, ks);
    }

    if let Some(path) = &args.adv_filelist {
        let ks = get_key_store(&mut key_store, args.keys.as_deref())?;
        return crate::ops::info::file_list(path, ks);
    }

    if let Some(path) = &args.dspl {
        let ks = get_key_store(&mut key_store, args.keys.as_deref())?;
        let output_dir = args.ofolder.as_deref().unwrap_or("./split");
        return crate::ops::dspl::split_to_files(path, output_dir, &args.output_type, ks);
    }

    if let Some(output_path) = &args.create {
        let ks = get_key_store(&mut key_store, args.keys.as_deref())?;
        let input_dir = args.ifolder.as_deref().ok_or_else(|| {
            crate::error::NscbError::InvalidData(
                "--create requires --ifolder <input_folder>".to_string(),
            )
        })?;
        return crate::ops::create::create_from_folder(input_dir, output_path, ks);
    }

    if let Some(path) = &args.direct_creation {
        let ks = get_key_store(&mut key_store, args.keys.as_deref())?;
        let output = make_output_path(path, &args.ofolder, &change_ext(path, &args.output_type));
        return crate::ops::convert::convert(path, &output, &args.output_type, ks);
    }

    if let Some(path) = &args.compress {
        let ks = get_key_store(&mut key_store, args.keys.as_deref())?;
        let output = make_output_path(path, &args.ofolder, &compress_ext(path));
        return crate::ops::compress::compress(path, &output, args.level, ks);
    }

    if let Some(path) = &args.decompress {
        let output = make_output_path(path, &args.ofolder, &decompress_ext(path));
        return crate::ops::decompress::decompress(path, &output);
    }

    eprintln!("No operation specified. Use --help for usage.");
    Ok(())
}

fn get_key_store<'a>(
    cache: &'a mut Option<KeyStore>,
    explicit_path: Option<&str>,
) -> Result<&'a KeyStore> {
    if cache.is_none() {
        *cache = Some(KeyStore::from_default_locations(explicit_path)?);
    }
    Ok(cache.as_ref().expect("key store initialized"))
}

impl RenameOptions {
    fn from_args(
        renmode: Option<&str>,
        addlangue: Option<&str>,
        noversion: Option<&str>,
        dlcrname: Option<&str>,
    ) -> Self {
        let mode = match renmode.map(|value| value.to_ascii_lowercase()) {
            Some(value) if value == "force" => RenameMode::Force,
            Some(value) if value == "skip_if_tid" => RenameMode::SkipIfTid,
            _ => RenameMode::SkipCorrectTid,
        };
        let add_language = matches!(
            addlangue.map(|value| value.eq_ignore_ascii_case("true")),
            Some(true)
        );
        let no_version = match noversion.map(|value| value.to_ascii_lowercase()) {
            Some(value) if value == "true" => NoVersionMode::Omit,
            Some(value) if value == "xci_no_v0" => NoVersionMode::XciNoV0,
            _ => NoVersionMode::Keep,
        };
        let dlc_mode = match dlcrname.map(|value| value.to_ascii_lowercase()) {
            Some(value) if value == "tag" => DlcRenameMode::AppendTag,
            Some(value) if value == "true" => DlcRenameMode::PreferControlTitle,
            _ => DlcRenameMode::KeepBaseStyle,
        };

        Self {
            mode,
            add_language,
            no_version,
            dlc_mode,
        }
    }
}

fn rename_target(
    path: &str,
    ks: &KeyStore,
    nutdb: &crate::nutdb::NutdbIndex,
    options: RenameOptions,
) -> Result<usize> {
    let path = Path::new(path);
    let mut targets = Vec::new();
    collect_rename_targets(path, &mut targets)?;
    if targets.is_empty() {
        return Err(crate::error::NscbError::InvalidData(format!(
            "No supported files found under {}",
            path.display()
        )));
    }

    let mut renamed = 0usize;
    for target in targets {
        if rename_single_file(&target, ks, nutdb, options)? {
            renamed += 1;
        }
    }
    Ok(renamed)
}

fn collect_rename_targets(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if path.is_file() {
        if is_supported_rename_extension(path)
            && !is_ignored_merge_input_path(&path.to_string_lossy())
        {
            out.push(path.to_path_buf());
        }
        return Ok(());
    }

    if !path.is_dir() {
        return Err(crate::error::NscbError::InvalidData(format!(
            "Path does not exist or is not accessible: {}",
            path.display()
        )));
    }

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        if entry_path.is_dir() {
            collect_rename_targets(&entry_path, out)?;
        } else if is_supported_rename_extension(&entry_path)
            && !is_ignored_merge_input_path(&entry_path.to_string_lossy())
        {
            out.push(entry_path);
        }
    }
    Ok(())
}

fn is_supported_rename_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "nsp" | "nsx" | "nsz" | "xci" | "xcz"
            )
        })
        .unwrap_or(false)
}

fn rename_single_file(
    path: &Path,
    ks: &KeyStore,
    nutdb: &crate::nutdb::NutdbIndex,
    options: RenameOptions,
) -> Result<bool> {
    let path_str = path.to_string_lossy().to_string();
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .ok_or_else(|| crate::error::NscbError::InvalidData("Missing file extension".to_string()))?
        .to_ascii_lowercase();

    let plan = build_rename_plan_metadata(&path_str, ks, nutdb);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_string();

    if should_skip_rename(&file_name, plan.as_ref(), options.mode) {
        return Ok(false);
    }

    let filename = plan
        .as_ref()
        .map(|plan| build_rename_filename_from_plan(plan, &extension, nutdb, options))
        .unwrap_or_else(|| build_rename_filename_fallback(&path_str, &extension));
    let target_name = sanitize_output_filename(&filename);

    if file_name == target_name {
        return Ok(false);
    }

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let target_path = dedupe_rename_target(parent, &target_name, path);
    fs::rename(path, &target_path)?;
    println!("{} -> {}", path.display(), target_path.display());
    Ok(true)
}

fn dedupe_rename_target(parent: &Path, target_name: &str, original_path: &Path) -> PathBuf {
    let candidate = parent.join(target_name);
    if same_path_case_insensitive(&candidate, original_path) || !candidate.exists() {
        return candidate;
    }

    let stem = Path::new(target_name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("renamed");
    let ext = Path::new(target_name)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{e}"))
        .unwrap_or_default();
    let mut deduped = format!("{stem} (SeemsDuplicate){ext}");
    let mut candidate = parent.join(&deduped);
    let mut counter = 1usize;
    while candidate.exists() && !same_path_case_insensitive(&candidate, original_path) {
        deduped = format!("{stem} (SeemsDuplicate {counter}){ext}");
        candidate = parent.join(&deduped);
        counter += 1;
    }
    candidate
}

fn same_path_case_insensitive(a: &Path, b: &Path) -> bool {
    a.to_string_lossy()
        .replace('\\', "/")
        .eq_ignore_ascii_case(&b.to_string_lossy().replace('\\', "/"))
}

fn should_skip_rename(file_name: &str, plan: Option<&RenameNamePlan>, mode: RenameMode) -> bool {
    match mode {
        RenameMode::Force => false,
        RenameMode::SkipIfTid => filename_contains_any_title_id(file_name),
        RenameMode::SkipCorrectTid => plan
            .map(|plan| {
                file_name
                    .to_ascii_uppercase()
                    .contains(&format!("[{}]", plan.title_id))
            })
            .unwrap_or(false),
    }
}

fn filename_contains_any_title_id(file_name: &str) -> bool {
    Regex::new(r"\[([0-9A-Fa-f]{16})\]")
        .unwrap()
        .captures_iter(file_name)
        .next()
        .is_some()
}

/// Build output path: if ofolder is set, put the file there; otherwise use the derived name.
fn make_output_path(_input: &str, ofolder: &Option<String>, default_name: &str) -> String {
    let file_name = Path::new(default_name)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let mut safe_file_name = sanitize_output_filename(&file_name);
    if file_name.contains("][") {
        safe_file_name = Regex::new(r"\]\s+\[")
            .unwrap()
            .replace_all(&safe_file_name, "][")
            .to_string();
    }

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
    let renamed = p.with_extension(new_ext).to_string_lossy().to_string();
    Regex::new(r"\]\s+\[")
        .unwrap()
        .replace_all(&renamed, "][")
        .to_string()
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
    let name = python_title_spacing(&game_name.unwrap_or_else(|| "merged".to_string()));
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

#[derive(Debug, Clone)]
struct RenameNamePlan {
    selected_kind: MergeKind,
    title_id: String,
    version: u32,
    display_name: String,
    content_suffix: String,
    base_title_id: Option<String>,
    update_title_id: Option<String>,
    dlc_title_id: Option<String>,
    language_tag: Option<String>,
    used_fallback_title: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RenameMode {
    Force,
    SkipCorrectTid,
    SkipIfTid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoVersionMode {
    Keep,
    Omit,
    XciNoV0,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DlcRenameMode {
    KeepBaseStyle,
    PreferControlTitle,
    AppendTag,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RenameOptions {
    mode: RenameMode,
    add_language: bool,
    no_version: NoVersionMode,
    dlc_mode: DlcRenameMode,
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
    nutdb: &NutdbStore,
) -> Option<String> {
    let (records, latest_version, title_name) = collect_title_records(input_paths, ks);
    if records.is_empty() {
        return None;
    }

    let plan = build_name_plan(
        &records,
        latest_version,
        title_name,
        nutdb.try_load_cached_index().ok().flatten().as_ref(),
        input_paths.first().copied().unwrap_or("merged"),
    );

    Some(format!(
        "{} [{}] [v{}]{}.{}",
        plan.display_name, plan.title_id, plan.version, plan.content_suffix, output_type
    ))
}

fn build_rename_plan_metadata(
    input_path: &str,
    ks: &KeyStore,
    nutdb: &crate::nutdb::NutdbIndex,
) -> Option<RenameNamePlan> {
    let (records, latest_version, title_name) = collect_title_records(&[input_path], ks);
    if records.is_empty() {
        return None;
    }

    let mut plan = build_name_plan(
        &records,
        latest_version,
        title_name,
        Some(nutdb),
        input_path,
    );
    plan.language_tag = crate::ops::info::control_language_tag(input_path, ks);
    Some(plan)
}

fn build_rename_filename_from_plan(
    plan: &RenameNamePlan,
    extension: &str,
    nutdb: &crate::nutdb::NutdbIndex,
    options: RenameOptions,
) -> String {
    let display_name = build_display_name_with_options(plan, nutdb, options);
    let version_tag = build_version_tag(plan, extension, options);
    format!(
        "{} [{}]{}{}.{}",
        display_name, plan.title_id, version_tag, plan.content_suffix, extension
    )
}

fn build_rename_filename_fallback(input_path: &str, extension: &str) -> String {
    let fallback = build_merge_filename(&[input_path], extension);
    let fallback = Path::new(&fallback)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(&fallback)
        .to_string();
    let original_stem = Path::new(input_path)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("UNKNOWN");
    if fallback.contains("[0000000000000000]") {
        format!("{original_stem} (needscheck).{extension}")
    } else {
        fallback
    }
}

fn build_name_plan(
    records: &HashMap<u64, MergeTitleRecord>,
    latest_version: Option<u32>,
    title_name: Option<String>,
    nutdb: Option<&crate::nutdb::NutdbIndex>,
    input_path: &str,
) -> RenameNamePlan {
    let mut base_count = 0u32;
    let mut update_count = 0u32;
    let mut dlc_count = 0u32;
    let mut base_tid: Option<u64> = None;
    let mut update_tid: Option<u64> = None;
    let mut dlc_tid: Option<u64> = None;

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
            MergeKind::Dlc => {
                dlc_count += 1;
                if dlc_tid.is_none() {
                    dlc_tid = Some(rec.title_id);
                }
            }
        }
    }

    let (selected_kind, selected_tid) = if let Some(tid) = base_tid {
        (MergeKind::Base, tid)
    } else if let Some(tid) = update_tid {
        (MergeKind::Update, tid)
    } else {
        (MergeKind::Dlc, dlc_tid.unwrap_or(0))
    };
    let selected_tid_str = format!("{selected_tid:016X}");

    let filtered_title_name = title_name.filter(|s| !s.trim().is_empty() && s != "DLC");
    let used_fallback_title = filtered_title_name.is_none()
        && nutdb
            .and_then(|index| {
                index
                    .display_name_for(&selected_tid_str)
                    .or_else(|| {
                        update_tid
                            .map(|tid| format!("{tid:016X}"))
                            .and_then(|tid| index.display_name_for(&tid))
                    })
                    .or_else(|| {
                        dlc_tid
                            .map(|tid| format!("{tid:016X}"))
                            .and_then(|tid| index.display_name_for(&tid))
                    })
            })
            .is_none();
    let name = filtered_title_name
        .filter(|s| !s.trim().is_empty() && s != "DLC")
        .or_else(|| {
            nutdb.and_then(|index| {
                index
                    .display_name_for(&selected_tid_str)
                    .or_else(|| {
                        update_tid
                            .map(|tid| format!("{tid:016X}"))
                            .and_then(|tid| index.display_name_for(&tid))
                    })
                    .or_else(|| {
                        dlc_tid
                            .map(|tid| format!("{tid:016X}"))
                            .and_then(|tid| index.display_name_for(&tid))
                    })
            })
        })
        .unwrap_or_else(|| infer_game_name_from_path(input_path));
    let display_name = python_title_spacing(&name);
    let version = latest_version.unwrap_or(0);
    let content_suffix = build_content_suffix(base_count, update_count, dlc_count);

    RenameNamePlan {
        selected_kind,
        title_id: selected_tid_str,
        version,
        display_name,
        content_suffix,
        base_title_id: base_tid.map(|tid| format!("{tid:016X}")),
        update_title_id: update_tid.map(|tid| format!("{tid:016X}")),
        dlc_title_id: dlc_tid.map(|tid| format!("{tid:016X}")),
        language_tag: None,
        used_fallback_title,
    }
}

fn build_content_suffix(base_count: u32, update_count: u32, dlc_count: u32) -> String {
    let mut summary = String::new();
    if base_count > 0 {
        summary.push_str(&format!("{base_count}G"));
    }
    if update_count > 0 {
        if !summary.is_empty() {
            summary.push('+');
        }
        summary.push_str(&format!("{update_count}U"));
    }
    if dlc_count > 0 {
        if !summary.is_empty() {
            summary.push('+');
        }
        summary.push_str(&format!("{dlc_count}D"));
    }

    if summary.is_empty() || summary == "1G" || summary == "1U" || summary == "1D" {
        String::new()
    } else {
        format!(" ({summary})")
    }
}

fn build_display_name_with_options(
    plan: &RenameNamePlan,
    nutdb: &crate::nutdb::NutdbIndex,
    options: RenameOptions,
) -> String {
    let mut display_name = match plan.selected_kind {
        MergeKind::Dlc => match (options.mode, options.dlc_mode) {
            (RenameMode::Force, DlcRenameMode::KeepBaseStyle) => nutdb
                .display_name_for(&plan.title_id)
                .unwrap_or_else(|| plan.display_name.clone()),
            (RenameMode::Force, DlcRenameMode::PreferControlTitle)
            | (RenameMode::SkipCorrectTid | RenameMode::SkipIfTid, DlcRenameMode::KeepBaseStyle)
            | (
                RenameMode::SkipCorrectTid | RenameMode::SkipIfTid,
                DlcRenameMode::PreferControlTitle,
            ) => python_dlc_lookup_name(plan, nutdb),
            (RenameMode::Force, DlcRenameMode::AppendTag) => {
                let mut base = nutdb
                    .display_name_for(&plan.title_id)
                    .unwrap_or_else(|| plan.display_name.clone());
                let dlc_tag = format!("[{}]", python_dlc_number_name(plan, true));
                if !base.contains(&dlc_tag) {
                    base.push(' ');
                    base.push_str(&dlc_tag);
                }
                base.replace("DLC number", "DLC")
            }
            (RenameMode::SkipCorrectTid | RenameMode::SkipIfTid, DlcRenameMode::AppendTag) => {
                python_dlc_lookup_name(plan, nutdb).replace("DLC number", "DLC")
            }
        },
        _ => plan.display_name.clone(),
    };

    if options.add_language {
        let language_source_id = plan
            .base_title_id
            .as_deref()
            .or(plan.update_title_id.as_deref())
            .or(Some(plan.title_id.as_str()))
            .unwrap_or(plan.title_id.as_str());
        let language_tag = plan
            .language_tag
            .clone()
            .or_else(|| format_language_tag(&nutdb.languages_for(language_source_id)));
        if let Some(tag) = language_tag {
            display_name.push(' ');
            display_name.push_str(&tag);
        }
    }

    python_title_spacing(&display_name)
}

fn python_dlc_lookup_name(plan: &RenameNamePlan, nutdb: &crate::nutdb::NutdbIndex) -> String {
    nutdb
        .display_name_for(&plan.title_id)
        .unwrap_or_else(|| python_dlc_number_name(plan, false))
}

fn python_dlc_number_name(plan: &RenameNamePlan, abbreviated: bool) -> String {
    let number = crate::nutdb::dlc_number(&plan.title_id);
    if abbreviated {
        format!("DLC {number}")
    } else {
        format!("DLC number {number}")
    }
}

fn build_version_tag(plan: &RenameNamePlan, extension: &str, options: RenameOptions) -> String {
    let omit = match options.no_version {
        NoVersionMode::Keep => false,
        NoVersionMode::Omit => plan.content_suffix.is_empty(),
        NoVersionMode::XciNoV0 => {
            matches!(extension, "xci" | "xcz")
                && plan.version == 0
                && plan.content_suffix.is_empty()
        }
    };
    if omit {
        String::new()
    } else {
        format!(" [v{}]", plan.version)
    }
}

fn format_language_tag(languages: &[String]) -> Option<String> {
    let mut seen = Vec::new();
    for lang in languages {
        let lower = lang.to_ascii_lowercase();
        let mapped = if lower.contains("us")
            || lower == "en"
            || lower.contains("eng")
            || lower.contains("uk")
        {
            Some("En")
        } else if lower.contains("jp") || lower == "ja" || lower.contains("jpn") {
            Some("Jp")
        } else if lower == "fr" || lower.contains("cad") || lower.contains("french") {
            Some("Fr")
        } else if lower == "de" || lower.contains("german") {
            Some("De")
        } else if lower == "es" || lower.contains("spa") || lower.contains("spanish") {
            Some("Es")
        } else if lower == "it" || lower.contains("italian") {
            Some("It")
        } else if lower == "nl" || lower.contains("dutch") || lower == "du" {
            Some("Du")
        } else if lower == "pt" || lower.contains("por") || lower.contains("portuguese") {
            Some("Por")
        } else if lower == "ru" || lower.contains("russian") {
            Some("Ru")
        } else if lower == "ko" || lower.contains("kor") || lower.contains("korean") {
            Some("Kor")
        } else if lower == "zh"
            || lower.contains("tw")
            || lower.contains("ch")
            || lower.contains("chi")
            || lower.contains("hk")
        {
            Some("Ch")
        } else {
            None
        };

        if let Some(code) = mapped {
            if !seen.contains(&code) {
                seen.push(code);
            }
        }
    }

    let ordered = [
        "En", "Jp", "Fr", "De", "Es", "It", "Du", "Por", "Ru", "Kor", "Ch",
    ]
    .into_iter()
    .filter(|code| seen.contains(code))
    .collect::<Vec<_>>();

    if ordered.is_empty() {
        None
    } else {
        Some(format!("({})", ordered.join(",")))
    }
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
                let _ = collect_title_records_from_nsp(
                    path_str,
                    ks,
                    &mut by_title,
                    &mut latest_version,
                    &mut title_name,
                );
            }
            "xci" => {
                let _ = collect_title_records_from_xci(
                    path_str,
                    ks,
                    &mut by_title,
                    &mut latest_version,
                    &mut title_name,
                );
            }
            _ => {
                // Decompressed temp files may not have extension.
                if collect_title_records_from_nsp(
                    path_str,
                    ks,
                    &mut by_title,
                    &mut latest_version,
                    &mut title_name,
                )
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
            if let Some(cnmt) =
                crate::ops::split::parse_cnmt_from_meta_nca(&mut file, abs_offset, ks)
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

    // Title lookup path similar to squirrel.get_title(): read CONTROL NCA -> NACP title.
    if title_name.is_none() {
        for entry in nsp.nca_entries() {
            if let Ok(info) = crate::formats::nca::parse_nca_info(
                &mut file,
                nsp.file_abs_offset(entry),
                entry.size,
                &entry.name,
                ks,
            ) {
                if info.content_type == Some(ContentType::Control) {
                    let abs_offset = nsp.file_abs_offset(entry);
                    if let Some(name) = crate::ops::split::parse_nacp_title_from_control_nca(
                        &mut file, abs_offset, ks,
                    ) {
                        *title_name = Some(name);
                        break;
                    }
                }
            }
        }
    }

    if found_any {
        Ok(())
    } else {
        Err(())
    }
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
        if let Ok(info) = crate::formats::nca::parse_nca_info(
            &mut file,
            entry.abs_offset,
            entry.size,
            &entry.name,
            ks,
        ) {
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
                if let Some(name) = crate::ops::split::parse_nacp_title_from_control_nca(
                    &mut file,
                    entry.abs_offset,
                    ks,
                ) {
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

    if found_any {
        Ok(())
    } else {
        Err(())
    }
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

fn python_title_spacing(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return "merged".to_string();
    }
    let has_non_ascii = trimmed.chars().any(|ch| !ch.is_ascii());
    let has_ascii_alpha = trimmed.chars().any(|ch| ch.is_ascii_alphabetic());
    if has_non_ascii && !has_ascii_alpha {
        let compact: Vec<char> = trimmed.chars().filter(|ch| !ch.is_whitespace()).collect();
        return compact
            .iter()
            .map(|ch| ch.to_string())
            .collect::<Vec<_>>()
            .join(" ");
    }
    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        build_content_suffix, build_display_name_with_options, build_merge_filename,
        build_name_plan, build_rename_filename_fallback, build_version_tag, change_ext,
        format_language_tag, make_output_path, sanitize_output_filename, should_skip_rename,
        DlcRenameMode, MergeKind, MergeTitleRecord, NoVersionMode, RenameMode, RenameNamePlan,
        RenameOptions,
    };
    use crate::nutdb::{NutdbIndex, NutdbTitle};
    use std::collections::HashMap;

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

    #[test]
    fn direct_creation_change_ext_collapses_adjacent_tag_spacing() {
        let out = change_ext(
            "/tmp/UNICORN OVERLORD[010054B01AD92000] [HK] [v0].xci",
            "nsp",
        );
        assert_eq!(out, "/tmp/UNICORN OVERLORD[010054B01AD92000][HK][v0].nsp");
    }

    #[test]
    fn direct_creation_make_output_path_preserves_collapsed_tags() {
        let default_name = "/tmp/UNICORN OVERLORD[010054B01AD92000][HK][v0].nsp".to_string();
        let out = make_output_path(
            "/mnt/e/test/UNICORN OVERLORD[010054B01AD92000][HK][v0].xci",
            &Some("/tmp/out".to_string()),
            &default_name,
        );
        assert_eq!(
            out,
            "/tmp/out/UNICORN OVERLORD[010054B01AD92000][HK][v0].nsp"
        );
    }

    #[test]
    fn content_suffix_matches_python_single_and_multi_rules() {
        assert_eq!(build_content_suffix(1, 0, 0), "");
        assert_eq!(build_content_suffix(1, 1, 0), " (1G+1U)");
        assert_eq!(build_content_suffix(0, 0, 3), " (3D)");
    }

    #[test]
    fn rename_plan_uses_dlc_name_from_nutdb() {
        let mut records = HashMap::new();
        records.insert(
            0x0100F8F0000A3401,
            MergeTitleRecord {
                title_id: 0x0100F8F0000A3401,
                version: 0,
                kind: MergeKind::Dlc,
            },
        );

        let mut titles = HashMap::new();
        titles.insert(
            "0100F8F0000A2000".to_string(),
            NutdbTitle {
                name: Some("Base Game".to_string()),
                publisher: None,
                languages: vec![],
                version: Some(0),
            },
        );
        titles.insert(
            "0100F8F0000A3401".to_string(),
            NutdbTitle {
                name: Some("Expansion Pack".to_string()),
                publisher: None,
                languages: vec![],
                version: Some(0),
            },
        );
        let index = NutdbIndex {
            source_url: "test".to_string(),
            titles,
        };

        let plan = build_name_plan(
            &records,
            Some(0),
            None,
            Some(&index),
            "ignored/path/file.nsp",
        );

        assert_eq!(plan.title_id, "0100F8F0000A3401");
        assert_eq!(plan.display_name, "Base Game [Expansion Pack]");
        assert_eq!(plan.content_suffix, "");
    }

    #[test]
    fn rename_fallback_marks_unresolved_files_for_checking() {
        let fallback = build_rename_filename_fallback("/tmp/Unknown Dump.nsp", "nsp");
        assert_eq!(fallback, "Unknown Dump (needscheck).nsp");
    }

    #[test]
    fn rename_options_parse_python_style_values() {
        let opts = RenameOptions::from_args(
            Some("skip_if_tid"),
            Some("true"),
            Some("xci_no_v0"),
            Some("tag"),
        );
        assert_eq!(opts.mode, RenameMode::SkipIfTid);
        assert!(opts.add_language);
        assert_eq!(opts.no_version, NoVersionMode::XciNoV0);
        assert_eq!(opts.dlc_mode, DlcRenameMode::AppendTag);
    }

    #[test]
    fn renmode_skip_if_tid_detects_existing_title_id() {
        assert!(should_skip_rename(
            "Game [0100F8F0000A2000].nsp",
            None,
            RenameMode::SkipIfTid
        ));
        assert!(!should_skip_rename(
            "Game Without Tid.nsp",
            None,
            RenameMode::SkipIfTid
        ));
    }

    #[test]
    fn renmode_skip_correct_tid_only_skips_matching_id() {
        let plan = RenameNamePlan {
            selected_kind: MergeKind::Base,
            title_id: "0100F8F0000A2000".to_string(),
            version: 0,
            display_name: "Base Game".to_string(),
            content_suffix: String::new(),
            base_title_id: Some("0100F8F0000A2000".to_string()),
            update_title_id: None,
            dlc_title_id: None,
            language_tag: None,
            used_fallback_title: false,
        };
        assert!(should_skip_rename(
            "Base Game [0100F8F0000A2000].nsp",
            Some(&plan),
            RenameMode::SkipCorrectTid
        ));
        assert!(!should_skip_rename(
            "Base Game [0100F8F0000A2800].nsp",
            Some(&plan),
            RenameMode::SkipCorrectTid
        ));
    }

    #[test]
    fn noversion_modes_match_expected_behavior() {
        let base_plan = RenameNamePlan {
            selected_kind: MergeKind::Base,
            title_id: "0100F8F0000A2000".to_string(),
            version: 0,
            display_name: "Base Game".to_string(),
            content_suffix: String::new(),
            base_title_id: Some("0100F8F0000A2000".to_string()),
            update_title_id: None,
            dlc_title_id: None,
            language_tag: None,
            used_fallback_title: false,
        };

        assert_eq!(
            build_version_tag(
                &base_plan,
                "nsp",
                RenameOptions {
                    mode: RenameMode::Force,
                    add_language: false,
                    no_version: NoVersionMode::Omit,
                    dlc_mode: DlcRenameMode::KeepBaseStyle,
                }
            ),
            ""
        );
        assert_eq!(
            build_version_tag(
                &base_plan,
                "xci",
                RenameOptions {
                    mode: RenameMode::Force,
                    add_language: false,
                    no_version: NoVersionMode::XciNoV0,
                    dlc_mode: DlcRenameMode::KeepBaseStyle,
                }
            ),
            ""
        );
    }

    #[test]
    fn language_tag_formats_expected_codes() {
        let langs = vec!["en".to_string(), "fr".to_string(), "ja".to_string()];
        assert_eq!(format_language_tag(&langs).as_deref(), Some("(En,Jp,Fr)"));
    }

    #[test]
    fn dlc_tag_mode_appends_numeric_dlc_tag() {
        let plan = RenameNamePlan {
            selected_kind: MergeKind::Dlc,
            title_id: "0100F8F0000A3401".to_string(),
            version: 0,
            display_name: "Base Game [Expansion Pack]".to_string(),
            content_suffix: String::new(),
            base_title_id: Some("0100F8F0000A2000".to_string()),
            update_title_id: None,
            dlc_title_id: Some("0100F8F0000A3401".to_string()),
            language_tag: None,
            used_fallback_title: false,
        };
        let index = NutdbIndex {
            source_url: "test".to_string(),
            titles: HashMap::new(),
        };
        let out = build_display_name_with_options(
            &plan,
            &index,
            RenameOptions {
                mode: RenameMode::Force,
                add_language: false,
                no_version: NoVersionMode::Keep,
                dlc_mode: DlcRenameMode::AppendTag,
            },
        );
        assert_eq!(out, "Base Game [Expansion Pack] [DLC 1025]");
    }

    #[test]
    fn addlangue_prefers_package_language_tag() {
        let plan = RenameNamePlan {
            selected_kind: MergeKind::Base,
            title_id: "0100F8F0000A2000".to_string(),
            version: 0,
            display_name: "Base Game".to_string(),
            content_suffix: String::new(),
            base_title_id: Some("0100F8F0000A2000".to_string()),
            update_title_id: None,
            dlc_title_id: None,
            language_tag: Some("(Kor,Ch)".to_string()),
            used_fallback_title: false,
        };
        let index = NutdbIndex {
            source_url: "test".to_string(),
            titles: HashMap::new(),
        };
        let out = build_display_name_with_options(
            &plan,
            &index,
            RenameOptions {
                mode: RenameMode::SkipCorrectTid,
                add_language: true,
                no_version: NoVersionMode::Keep,
                dlc_mode: DlcRenameMode::KeepBaseStyle,
            },
        );
        assert_eq!(out, "Base Game (Kor,Ch)");
    }

    #[test]
    fn dlc_tag_mode_matches_python_non_force_cleanup() {
        let plan = RenameNamePlan {
            selected_kind: MergeKind::Dlc,
            title_id: "0100F8F0000A3401".to_string(),
            version: 0,
            display_name: "Tagged DLC".to_string(),
            content_suffix: String::new(),
            base_title_id: Some("0100F8F0000A2000".to_string()),
            update_title_id: None,
            dlc_title_id: Some("0100F8F0000A3401".to_string()),
            language_tag: None,
            used_fallback_title: true,
        };
        let index = NutdbIndex {
            source_url: "test".to_string(),
            titles: HashMap::new(),
        };
        let out = build_display_name_with_options(
            &plan,
            &index,
            RenameOptions {
                mode: RenameMode::SkipCorrectTid,
                add_language: false,
                no_version: NoVersionMode::Keep,
                dlc_mode: DlcRenameMode::AppendTag,
            },
        );
        assert_eq!(out, "DLC 1025");
    }
}
