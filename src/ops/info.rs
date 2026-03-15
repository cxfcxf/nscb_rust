use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom};
use std::path::Path;

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;

use crate::crypto::aes_xts::NintendoXts;
use crate::error::{NscbError, Result};
use crate::formats::cnmt::Cnmt;
use crate::formats::nca::{self, NcaHeader};
use crate::formats::nsp::Nsp;
use crate::formats::pfs0::Pfs0;
use crate::formats::ticket::Ticket;
use crate::formats::types::{ContentType, TitleType};
use crate::formats::xci::Xci;
use crate::keys::KeyStore;
use crate::ops::split::{group_nsp_entries, group_xci_entries, parse_cnmt_from_meta_nca};

pub fn content_list(path: &str, ks: &KeyStore) -> Result<()> {
    let report = build_report(path, ks)?;
    print!("{}", build_adv_content_text(&report));
    Ok(())
}

pub fn file_list(path: &str, ks: &KeyStore) -> Result<()> {
    let report = build_report(path, ks)?;
    print!("{}", build_adv_file_text(&report));
    Ok(())
}

pub(crate) fn control_language_tag(path: &str, ks: &KeyStore) -> Option<String> {
    let report = build_report(path, ks).ok()?;
    let title = report
        .titles
        .iter()
        .find(|title| matches!(title.title_type, TitleType::Application | TitleType::Patch))
        .or_else(|| report.titles.first())?;
    python_language_tag_from_labels(&title.control.languages)
}

#[derive(Clone)]
struct Report {
    titles: Vec<TitleReport>,
}

#[derive(Clone)]
struct TitleReport {
    title_id: u64,
    base_id: u64,
    version: u32,
    title_type: TitleType,
    required_system_version: u32,
    key_generation: u8,
    meta_sdk_version: String,
    content_sdk_version: String,
    control: ControlInfo,
    content_entries: Vec<ContentEntryReport>,
    meta_name: String,
    meta_size: u64,
}

#[derive(Clone)]
struct ContentEntryReport {
    name: String,
    size: u64,
    ncatype: u8,
}

#[derive(Clone, Default)]
struct ControlInfo {
    title: String,
    publisher: String,
    display_version: String,
    languages: Vec<&'static str>,
}

#[derive(Clone, Default)]
struct GroupAnalysis {
    cnmt: Option<Cnmt>,
    meta_name: String,
    meta_size: u64,
    meta_sdk_version: String,
    key_generation: u8,
    program_sdk_version: String,
    data_sdk_version: String,
    control: Option<ControlInfo>,
}

fn build_report(path: &str, ks: &KeyStore) -> Result<Report> {
    match ext(path).as_str() {
        "nsp" | "nsz" => build_report_nsp(path, ks),
        "xci" | "xcz" => build_report_xci(path, ks),
        other => Err(NscbError::UnsupportedFormat(format!(
            "Cannot inspect {}",
            other
        ))),
    }
}

fn build_report_nsp(path: &str, ks: &KeyStore) -> Result<Report> {
    let mut file = BufReader::new(File::open(path)?);
    let nsp = Nsp::parse(&mut file)?;
    let groups = group_nsp_entries(&nsp, &mut file, path, ks)?;
    let mut report = build_report_from_groups(&mut file, &groups, ks)?;
    apply_nsp_cnmt_xml_overrides(&mut file, &nsp, &mut report)?;
    Ok(report)
}

fn build_report_xci(path: &str, ks: &KeyStore) -> Result<Report> {
    let mut file = BufReader::new(File::open(path)?);
    let xci = Xci::parse(&mut file)?;
    let groups = group_xci_entries(&xci, &mut file, path, ks)?;
    build_report_from_groups(&mut file, &groups, ks)
}

fn build_report_from_groups<R: Read + Seek>(
    reader: &mut R,
    groups: &[crate::ops::split::TitleGroup],
    ks: &KeyStore,
) -> Result<Report> {
    let mut titles = Vec::new();

    for group in groups {
        let analysis = analyze_group(reader, group, ks)?;
        let Some(cnmt) = analysis.cnmt.as_ref() else {
            continue;
        };

        let title_type = cnmt.title_type_enum().unwrap_or_else(|| {
            group
                .title_type
                .unwrap_or_else(|| infer_title_type(group.title_id))
        });
        let base_id = match title_type {
            TitleType::Application => cnmt.title_id,
            TitleType::Patch | TitleType::AddOnContent | TitleType::Delta => {
                cnmt.application_title_id
            }
            _ => cnmt.title_id,
        };

        let mut content_entries = Vec::new();
        for content in &cnmt.content_entries {
            content_entries.push(ContentEntryReport {
                name: format!("{}.nca", content.nca_id()),
                size: content.size,
                ncatype: content.content_type,
            });
        }

        titles.push(TitleReport {
            title_id: cnmt.title_id,
            base_id,
            version: cnmt.version,
            title_type,
            required_system_version: cnmt.required_system_version,
            key_generation: analysis.key_generation,
            meta_sdk_version: analysis.meta_sdk_version,
            content_sdk_version: if title_type == TitleType::AddOnContent {
                analysis.data_sdk_version
            } else {
                analysis.program_sdk_version
            },
            control: analysis.control.unwrap_or_default(),
            content_entries,
            meta_name: analysis.meta_name,
            meta_size: analysis.meta_size,
        });
    }

    let mut base_control = BTreeMap::new();
    let mut base_program_sdk = BTreeMap::new();
    for title in &titles {
        if title.title_type == TitleType::Application {
            base_control.insert(title.title_id, title.control.clone());
            base_program_sdk.insert(title.title_id, title.content_sdk_version.clone());
        }
    }

    for title in &mut titles {
        if title.title_type == TitleType::Patch {
            if let Some(control) = base_control.get(&title.base_id) {
                if title.control.title.is_empty() {
                    title.control.title = control.title.clone();
                }
                if title.control.publisher.is_empty() {
                    title.control.publisher = control.publisher.clone();
                }
                if title.control.languages.is_empty() {
                    title.control.languages = control.languages.clone();
                }
            }
            if title.control.display_version.is_empty() || title.control.display_version == "-" {
                title.control.display_version = fallback_patch_display_version(title.version);
            }
            if let Some(program_sdk) = base_program_sdk.get(&title.base_id) {
                title.content_sdk_version = program_sdk.clone();
            }
        }
    }

    titles.sort_by_key(|title| (title.base_id, title_sort_rank(title), title.title_id));
    Ok(Report { titles })
}

fn python_language_tag_from_labels(labels: &[&'static str]) -> Option<String> {
    if labels.is_empty() {
        return None;
    }

    let mut out = String::from("(");
    if labels.contains(&"US (eng)") || labels.contains(&"UK (eng)") {
        out.push_str("En,");
    }
    if labels.contains(&"JP") {
        out.push_str("Jp,");
    }
    if labels.contains(&"CAD (fr)") || labels.contains(&"FR") {
        out.push_str("Fr,");
    }
    if labels.contains(&"DE") {
        out.push_str("De,");
    }
    if labels.contains(&"LAT (spa)") && labels.contains(&"SPA") {
        out.push_str("Es,");
    } else if labels.contains(&"LAT (spa)") {
        out.push_str("LatEs,");
    } else if labels.contains(&"SPA") {
        out.push_str("Es,");
    }
    if labels.contains(&"IT") {
        out.push_str("It,");
    }
    if labels.contains(&"DU") {
        out.push_str("Du,");
    }
    if labels.contains(&"POR") {
        out.push_str("Por,");
    }
    if labels.contains(&"RU") {
        out.push_str("Ru,");
    }
    if labels.contains(&"KOR") {
        out.push_str("Kor,");
    }
    if labels.contains(&"CH") || labels.contains(&"TW (ch)") {
        out.push_str("Ch,");
    }

    if out == "(" {
        None
    } else {
        out.pop();
        out.push(')');
        Some(out)
    }
}

fn analyze_group<R: Read + Seek>(
    reader: &mut R,
    group: &crate::ops::split::TitleGroup,
    ks: &KeyStore,
) -> Result<GroupAnalysis> {
    let mut analysis = GroupAnalysis::default();
    let mut title_keys_by_rights = BTreeMap::new();

    for entry in &group.entries {
        if !entry.name.ends_with(".tik") {
            continue;
        }
        reader.seek(SeekFrom::Start(entry.abs_offset))?;
        let mut raw = vec![0u8; entry.size as usize];
        reader.read_exact(&mut raw)?;
        if let Ok(ticket) = Ticket::from_bytes(&raw) {
            if let Ok(title_key) = ticket.decrypt_title_key(ks) {
                title_keys_by_rights.insert(ticket.rights_id, title_key);
            }
        }
    }

    for entry in &group.entries {
        let lower = entry.name.to_ascii_lowercase();
        if !(lower.ends_with(".nca") || lower.ends_with(".ncz")) {
            continue;
        }

        let info = match nca::parse_nca_info(reader, entry.abs_offset, entry.size, &entry.name, ks)
        {
            Ok(info) => info,
            Err(_) => continue,
        };

        match info.content_type {
            Some(ContentType::Meta) => {
                if let Ok(header) = NcaHeader::from_reader(reader, entry.abs_offset, ks) {
                    analysis.meta_sdk_version = format_sdk_version(header.sdk_version);
                    analysis.key_generation = header.key_generation();
                }
                if let Some(cnmt) = parse_cnmt_from_meta_nca(reader, entry.abs_offset, ks) {
                    analysis.cnmt = Some(cnmt);
                    analysis.meta_name = entry.name.clone();
                    analysis.meta_size = entry.size;
                }
            }
            Some(ContentType::Program) => {
                if analysis.program_sdk_version.is_empty() {
                    if let Ok(header) = NcaHeader::from_reader(reader, entry.abs_offset, ks) {
                        analysis.program_sdk_version = format_sdk_version(header.sdk_version);
                    }
                }
            }
            Some(ContentType::Data) | Some(ContentType::PublicData) => {
                if analysis.data_sdk_version.is_empty() {
                    if let Ok(header) = NcaHeader::from_reader(reader, entry.abs_offset, ks) {
                        analysis.data_sdk_version = format_sdk_version(header.sdk_version);
                    }
                }
            }
            Some(ContentType::Control) => {
                let title_key =
                    if let Ok(header) = NcaHeader::from_reader(reader, entry.abs_offset, ks) {
                        title_keys_by_rights.get(&header.rights_id).copied()
                    } else {
                        None
                    };
                if analysis.control.is_none() {
                    let mut control =
                        read_control_info(reader, entry.abs_offset, ks, title_key.as_ref())
                            .unwrap_or_default();
                    if control.display_version.is_empty() || control.display_version == "-" {
                        if let Some(display_version) = read_control_display_version(
                            reader,
                            entry.abs_offset,
                            ks,
                            title_key.as_ref(),
                        ) {
                            control.display_version = display_version;
                        }
                    }
                    if !control.title.is_empty()
                        || !control.publisher.is_empty()
                        || !control.display_version.is_empty()
                    {
                        analysis.control = Some(control);
                    }
                }
            }
            _ => {}
        }
    }

    Ok(analysis)
}

fn apply_nsp_cnmt_xml_overrides<R: Read + Seek>(
    reader: &mut R,
    nsp: &Nsp,
    report: &mut Report,
) -> Result<()> {
    let mut overrides = HashMap::new();
    for entry in nsp.all_entries() {
        if !entry.name.to_ascii_lowercase().ends_with(".cnmt.xml") {
            continue;
        }
        let data = nsp.pfs0.read_file(reader, &entry.name)?;
        if let Some(rsv) = parse_cnmt_xml_required_system_version(&data) {
            overrides.insert(entry.name.to_ascii_lowercase(), rsv);
        }
    }

    for title in &mut report.titles {
        let xml_name =
            format!("{}.xml", title.meta_name.trim_end_matches(".nca")).to_ascii_lowercase();
        if let Some(rsv) = overrides.get(&xml_name) {
            title.required_system_version = *rsv;
        }
    }
    Ok(())
}

fn parse_cnmt_xml_required_system_version(xml: &[u8]) -> Option<u32> {
    let text = std::str::from_utf8(xml).ok()?;
    let start_tag = "<RequiredSystemVersion>";
    let end_tag = "</RequiredSystemVersion>";
    let start = text.find(start_tag)? + start_tag.len();
    let end = text[start..].find(end_tag)? + start;
    text[start..end].trim().parse::<u32>().ok()
}

fn build_adv_content_text(report: &Report) -> String {
    let mut out = String::new();
    let mut grouped: BTreeMap<u64, Vec<&TitleReport>> = BTreeMap::new();
    for title in &report.titles {
        grouped.entry(title.base_id).or_default().push(title);
    }

    for titles in grouped.values() {
        let mut base = None;
        let mut updates = Vec::new();
        let mut dlcs = Vec::new();
        for title in titles {
            match title.title_type {
                TitleType::Application => base = Some(*title),
                TitleType::Patch => updates.push(*title),
                TitleType::AddOnContent => dlcs.push(*title),
                _ => {}
            }
        }

        if let Some(base_title) = base {
            push_line(&mut out, "------------------------------------------------");
            push_line(
                &mut out,
                &format!("BASE CONTENT ID: {}", lower_tid(base_title.base_id)),
            );
            push_line(&mut out, "------------------------------------------------");
            push_line(
                &mut out,
                &format!("Name: {}", python_spacing(&base_title.control.title)),
            );
            push_line(
                &mut out,
                &format!("Editor: {}", base_title.control.publisher),
            );
            push_line(&mut out, "------------------------------------------------");
            push_line(
                &mut out,
                &format!(
                    "{} [BASE] v{}",
                    lower_tid(base_title.title_id),
                    base_title.version
                ),
            );
            for update in &updates {
                push_line(
                    &mut out,
                    &format!(
                        "{} [UPD] v{} -> Patch({})",
                        lower_tid(update.title_id),
                        update.version,
                        update.version / 65_536
                    ),
                );
            }
            for dlc in &dlcs {
                push_line(
                    &mut out,
                    &format!(
                        "{} [DLC {}] v{}",
                        lower_tid(dlc.title_id),
                        dlc_number(dlc.title_id),
                        dlc.version
                    ),
                );
            }
            push_line(&mut out, "------------------------------------------------");
            push_line(
                &mut out,
                &format!(
                    "CONTENT INCLUDES: 1 BASEGAME {} UPDATES {} DLCS",
                    updates.len(),
                    dlcs.len()
                ),
            );
            push_line(&mut out, "------------------------------------------------");
            push_line(&mut out, "");
        }
    }

    out
}

fn build_adv_file_text(report: &Report) -> String {
    let mut out = String::new();

    for title in &report.titles {
        push_line(&mut out, "-----------------------------");
        push_line(
            &mut out,
            &format!("CONTENT ID: {}", lower_tid(title.title_id)),
        );
        push_line(&mut out, "-----------------------------");

        if title.title_type == TitleType::AddOnContent {
            if !title.control.title.is_empty() {
                push_line(
                    &mut out,
                    &format!("- Name: {}", python_spacing(&title.control.title)),
                );
                push_line(&mut out, &format!("- Editor: {}", title.control.publisher));
            }
            push_line(&mut out, "- Content type: DLC");
            let dlc_num = dlc_number(title.title_id);
            push_line(
                &mut out,
                &format!("- DLC number: {} -> AddOnContent ({})", dlc_num, dlc_num),
            );
            push_line(
                &mut out,
                &format!(
                    "- DLC version Number: {} -> Version ({})",
                    title.version,
                    title.version / 65_536
                ),
            );
            push_line(
                &mut out,
                &format!("- Meta SDK version: {}", title.meta_sdk_version),
            );
            push_line(
                &mut out,
                &format!("- Data SDK version: {}", title.content_sdk_version),
            );
            if !title.control.languages.is_empty() {
                push_line(
                    &mut out,
                    &format!(
                        "- Supported Languages: {}",
                        title.control.languages.join(", ")
                    ),
                );
            }
        } else {
            push_line(&mut out, "Titleinfo:");
            push_line(
                &mut out,
                &format!("- Name: {}", python_spacing(&title.control.title)),
            );
            push_line(&mut out, &format!("- Editor: {}", title.control.publisher));
            push_line(
                &mut out,
                &format!("- Display Version: {}", title.control.display_version),
            );
            push_line(
                &mut out,
                &format!("- Meta SDK version: {}", title.meta_sdk_version),
            );
            push_line(
                &mut out,
                &format!("- Program SDK version: {}", title.content_sdk_version),
            );
            push_line(
                &mut out,
                &format!(
                    "- Supported Languages: {}",
                    title.control.languages.join(", ")
                ),
            );
            push_line(
                &mut out,
                &format!(
                    "- Content type: {}",
                    python_content_type_label(title.title_type)
                ),
            );
            push_line(
                &mut out,
                &format!(
                    "- Version: {} -> {} ({})",
                    title.version,
                    python_cnmt_name(title.title_type),
                    title.version / 65_536
                ),
            );
        }

        push_line(&mut out, "");
        push_line(&mut out, "Required Firmware:");
        if title.title_type == TitleType::AddOnContent {
            push_line(
                &mut out,
                &format!(
                    "- Required game version: {} -> Application ({})",
                    title.required_system_version,
                    title.required_system_version / 65_536
                ),
            );
        } else {
            push_line(
                &mut out,
                &format!(
                    "- RequiredSystemVersion: {} -> {}",
                    title.required_system_version,
                    python_fw_range_rsv(title.required_system_version)
                ),
            );
        }
        push_line(
            &mut out,
            &format!(
                "- Encryption (keygeneration): {} -> {}",
                title.key_generation,
                python_fw_range_kg(title.key_generation)
            ),
        );
        if title.title_type == TitleType::AddOnContent {
            push_line(&mut out, "- Patchable to: DLC -> no RSV to patch");
            push_line(&mut out, "");
        } else {
            let min_rsv = python_min_rsv(title.key_generation, title.required_system_version);
            push_line(
                &mut out,
                &format!(
                    "- Patchable to: {} -> {}",
                    min_rsv,
                    python_fw_range_rsv(min_rsv)
                ),
            );
        }

        push_line(&mut out, "......................");
        push_line(&mut out, "NCA FILES (NON DELTAS)");
        push_line(&mut out, "......................");
        let mut total_non_delta = 0u64;
        for entry in title
            .content_entries
            .iter()
            .filter(|entry| entry.ncatype != 6)
        {
            push_line(&mut out, &python_nca_line(entry));
            total_non_delta += entry.size;
        }
        push_line(
            &mut out,
            &python_nca_line(&ContentEntryReport {
                name: title.meta_name.clone(),
                size: title.meta_size,
                ncatype: 0,
            }),
        );
        total_non_delta += title.meta_size;
        push_line(&mut out, "\t\t\t\t\t\t\t  --------------------");
        push_line(
            &mut out,
            &format!(
                "\t\t\t\t\t\t\t  TOTAL SIZE: {}",
                python_size(total_non_delta)
            ),
        );

        let full_total = total_non_delta;
        push_line(&mut out, "/////////////////////////////////////");
        push_line(
            &mut out,
            &format!("   FULL CONTENT TOTAL SIZE: {}   ", python_size(full_total)),
        );
        push_line(&mut out, "/////////////////////////////////////");
    }

    if !out.is_empty() {
        push_line(&mut out, "");
    }

    out
}

fn read_control_info<R: Read + Seek>(
    reader: &mut R,
    nca_abs_offset: u64,
    ks: &KeyStore,
    title_key: Option<&[u8; 16]>,
) -> Option<ControlInfo> {
    let header = NcaHeader::from_reader(reader, nca_abs_offset, ks).ok()?;
    let section_keys = candidate_section_keys(&header, ks, title_key);

    for sec_idx in 0..4 {
        let sec = &header.section_table[sec_idx];
        if !sec.is_present() || sec.size() == 0 || sec.size() > 64 * 1024 * 1024 {
            continue;
        }

        let sec_abs_offset = nca_abs_offset + sec.start_offset();
        let mut section_data = vec![0u8; sec.size() as usize];
        reader.seek(SeekFrom::Start(sec_abs_offset)).ok()?;
        reader.read_exact(&mut section_data).ok()?;

        if let Some(info) = parse_control_nca_section(&section_data) {
            return Some(info);
        }
        if let Some(info) = parse_control_info_from_section(&section_data) {
            return Some(info);
        }

        if let Some(keys) = &section_keys {
            let nonces = ctr_nonce_variants(header.section_ctr_nonce(sec_idx));
            for key in keys {
                for nonce in &nonces {
                    for &start in &[sec.start_offset(), 0u64] {
                        let mut dec_be = section_data.clone();
                        aes_ctr_transform_in_place(key, nonce, start, true, &mut dec_be);
                        if let Some(info) = parse_control_nca_section(&dec_be) {
                            return Some(info);
                        }
                        if let Some(info) = parse_control_info_from_section(&dec_be) {
                            return Some(info);
                        }

                        let mut dec_le = section_data.clone();
                        aes_ctr_transform_in_place(key, nonce, start, false, &mut dec_le);
                        if let Some(info) = parse_control_nca_section(&dec_le) {
                            return Some(info);
                        }
                        if let Some(info) = parse_control_info_from_section(&dec_le) {
                            return Some(info);
                        }
                    }
                }
            }

            if header.section_crypto_type(sec_idx) == 2 {
                let pairs = [(0usize, 1usize), (1, 0), (2, 3), (3, 2), (0, 2), (2, 0)];
                for (a, b) in pairs {
                    let mut xts_key = [0u8; 32];
                    xts_key[..16].copy_from_slice(&keys[a]);
                    xts_key[16..].copy_from_slice(&keys[b]);
                    let Ok(xts) = NintendoXts::new(&xts_key) else {
                        continue;
                    };
                    for &start_sector in &[(sec.start_offset() / 0x200), 0u64] {
                        for &le_sector in &[true, false] {
                            let mut dec = section_data.clone();
                            xts.decrypt_with_endian(start_sector, &mut dec, le_sector);
                            if let Some(info) = parse_control_nca_section(&dec) {
                                return Some(info);
                            }
                            if let Some(info) = parse_control_info_from_section(&dec) {
                                return Some(info);
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

fn read_control_display_version<R: Read + Seek>(
    reader: &mut R,
    nca_abs_offset: u64,
    ks: &KeyStore,
    title_key: Option<&[u8; 16]>,
) -> Option<String> {
    let header = NcaHeader::from_reader(reader, nca_abs_offset, ks).ok()?;
    let section_keys = candidate_section_keys(&header, ks, title_key);

    for sec_idx in 0..4 {
        let sec = &header.section_table[sec_idx];
        if !sec.is_present() || sec.size() == 0 || sec.size() > 64 * 1024 * 1024 {
            continue;
        }

        let sec_abs_offset = nca_abs_offset + sec.start_offset();
        let mut section_data = vec![0u8; sec.size() as usize];
        reader.seek(SeekFrom::Start(sec_abs_offset)).ok()?;
        reader.read_exact(&mut section_data).ok()?;

        let display = find_any_display_version(&section_data);
        if display != "-" {
            return Some(display);
        }

        if let Some(keys) = &section_keys {
            let nonces = ctr_nonce_variants(header.section_ctr_nonce(sec_idx));
            for key in keys {
                for nonce in &nonces {
                    for &start in &[sec.start_offset(), 0u64] {
                        let mut dec_be = section_data.clone();
                        aes_ctr_transform_in_place(key, nonce, start, true, &mut dec_be);
                        let display = find_any_display_version(&dec_be);
                        if display != "-" {
                            return Some(display);
                        }

                        let mut dec_le = section_data.clone();
                        aes_ctr_transform_in_place(key, nonce, start, false, &mut dec_le);
                        let display = find_any_display_version(&dec_le);
                        if display != "-" {
                            return Some(display);
                        }
                    }
                }
            }

            if header.section_crypto_type(sec_idx) == 2 {
                let pairs = [(0usize, 1usize), (1, 0), (2, 3), (3, 2), (0, 2), (2, 0)];
                for (a, b) in pairs {
                    let mut xts_key = [0u8; 32];
                    xts_key[..16].copy_from_slice(&keys[a]);
                    xts_key[16..].copy_from_slice(&keys[b]);
                    let Ok(xts) = NintendoXts::new(&xts_key) else {
                        continue;
                    };
                    for &start_sector in &[(sec.start_offset() / 0x200), 0u64] {
                        for &le_sector in &[true, false] {
                            let mut dec = section_data.clone();
                            xts.decrypt_with_endian(start_sector, &mut dec, le_sector);
                            let display = find_any_display_version(&dec);
                            if display != "-" {
                                return Some(display);
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

fn candidate_section_keys(
    header: &NcaHeader,
    ks: &KeyStore,
    title_key: Option<&[u8; 16]>,
) -> Option<Vec<[u8; 16]>> {
    if header.has_rights_id() {
        return title_key.map(|key| vec![*key]);
    }
    header.decrypt_key_area(ks).ok().map(|keys| keys.to_vec())
}

fn ctr_nonce_variants(raw: [u8; 8]) -> Vec<[u8; 8]> {
    let mut out = vec![raw];
    let be = u64::from_le_bytes(raw).to_be_bytes();
    if be != raw {
        out.push(be);
    }
    out
}

fn parse_control_nca_section(section_data: &[u8]) -> Option<ControlInfo> {
    if let Some(nacp) = extract_nacp_from_romfs(section_data) {
        if let Some(info) = parse_nacp_info(&nacp) {
            return Some(info);
        }
    }
    let offset = find_langueblock_offset(section_data)?;
    let display_version = find_display_version(section_data, offset);
    let languages = collect_supported_languages(section_data, offset);

    for idx in [0usize, 1, 6, 5, 7, 10, 3, 4, 9, 8, 2, 11, 12, 13, 14] {
        let base = offset + idx * 0x300;
        if base + 0x300 > section_data.len() {
            continue;
        }
        let title = clean_utf8(&section_data[base..base + 0x200]);
        let editor = clean_utf8(&section_data[base + 0x200..base + 0x300]);
        if title.is_empty() {
            continue;
        }
        let final_title = if title.is_empty() {
            "DLC".to_string()
        } else {
            title
        };
        return Some(ControlInfo {
            title: final_title,
            publisher: editor,
            display_version: display_version.clone(),
            languages,
        });
    }

    None
}

fn extract_nacp_from_romfs(section_data: &[u8]) -> Option<Vec<u8>> {
    if section_data.len() < 0x200 || section_data.get(0x8..0xC)? != b"IVFC" {
        return None;
    }

    let romfs_offset = u64::from_le_bytes(section_data.get(0x90..0x98)?.try_into().ok()?) as usize;
    let romfs_size = u64::from_le_bytes(section_data.get(0x98..0xA0)?.try_into().ok()?) as usize;
    let romfs = section_data.get(romfs_offset..romfs_offset.checked_add(romfs_size)?)?;
    if romfs.len() < 0x50 {
        return None;
    }

    let dir_table_offset = u64::from_le_bytes(romfs.get(0x18..0x20)?.try_into().ok()?) as usize;
    let dir_table_size = u64::from_le_bytes(romfs.get(0x20..0x28)?.try_into().ok()?) as usize;
    let file_table_offset = u64::from_le_bytes(romfs.get(0x38..0x40)?.try_into().ok()?) as usize;
    let file_table_size = u64::from_le_bytes(romfs.get(0x40..0x48)?.try_into().ok()?) as usize;
    let data_offset = u64::from_le_bytes(romfs.get(0x48..0x50)?.try_into().ok()?) as usize;

    let dir_table = romfs.get(dir_table_offset..dir_table_offset.checked_add(dir_table_size)?)?;
    let file_table =
        romfs.get(file_table_offset..file_table_offset.checked_add(file_table_size)?)?;

    extract_nacp_from_romfs_dir(romfs, dir_table, file_table, data_offset, 0)
}

fn extract_nacp_from_romfs_dir(
    romfs: &[u8],
    dir_table: &[u8],
    file_table: &[u8],
    data_offset: usize,
    dir_offset: usize,
) -> Option<Vec<u8>> {
    if dir_offset + 0x18 > dir_table.len() {
        return None;
    }

    let child_dir = u32::from_le_bytes(
        dir_table[dir_offset + 0x8..dir_offset + 0xC]
            .try_into()
            .ok()?,
    );
    let first_file = u32::from_le_bytes(
        dir_table[dir_offset + 0xC..dir_offset + 0x10]
            .try_into()
            .ok()?,
    );

    let mut file_offset = first_file;
    while file_offset != 0xFFFF_FFFF {
        let off = file_offset as usize;
        if off + 0x20 > file_table.len() {
            break;
        }
        let sibling = u32::from_le_bytes(file_table[off + 0x4..off + 0x8].try_into().ok()?);
        let data_rel =
            u64::from_le_bytes(file_table[off + 0x8..off + 0x10].try_into().ok()?) as usize;
        let size = u64::from_le_bytes(file_table[off + 0x10..off + 0x18].try_into().ok()?) as usize;
        let name_len =
            u32::from_le_bytes(file_table[off + 0x1C..off + 0x20].try_into().ok()?) as usize;
        let name_end = off + 0x20 + name_len;
        if name_end > file_table.len() {
            break;
        }
        let name = std::str::from_utf8(&file_table[off + 0x20..name_end]).ok()?;
        if name.ends_with(".nacp") {
            let data_start = data_offset.checked_add(data_rel)?;
            let data_end = data_start.checked_add(size)?;
            return romfs.get(data_start..data_end).map(|bytes| bytes.to_vec());
        }
        file_offset = sibling;
    }

    let mut next_dir = child_dir;
    while next_dir != 0xFFFF_FFFF {
        let off = next_dir as usize;
        if off + 0x18 > dir_table.len() {
            break;
        }
        if let Some(nacp) =
            extract_nacp_from_romfs_dir(romfs, dir_table, file_table, data_offset, off)
        {
            return Some(nacp);
        }
        next_dir = u32::from_le_bytes(dir_table[off + 0x4..off + 0x8].try_into().ok()?);
    }

    None
}

fn parse_control_info_from_section(section_data: &[u8]) -> Option<ControlInfo> {
    for off in pfs0_candidate_offsets(section_data) {
        let mut cursor = Cursor::new(section_data);
        let Ok(pfs) = Pfs0::parse_at(&mut cursor, off as u64) else {
            continue;
        };
        for entry in &pfs.entries {
            if entry.name.ends_with(".nacp") {
                let bytes = pfs.read_file(&mut cursor, &entry.name).ok()?;
                return parse_nacp_info(&bytes);
            }
        }
    }
    None
}

fn parse_nacp_info(bytes: &[u8]) -> Option<ControlInfo> {
    parse_nacp_info_at(bytes, 0)
}

fn parse_nacp_info_at(bytes: &[u8], base_offset: usize) -> Option<ControlInfo> {
    const ENTRY_SIZE: usize = 0x300;
    const TITLE_SIZE: usize = 0x200;
    const PUBLISHER_SIZE: usize = 0x100;
    const DISPLAY_VERSION_OFFSET: usize = 0x3060;
    const DISPLAY_VERSION_SIZE: usize = 0x10;
    const SUPPORTED_LANGUAGE_OFFSET: usize = 0x302C;
    const LABELS: [&str; 15] = [
        "US (eng)",
        "UK (eng)",
        "JP",
        "FR",
        "DE",
        "LAT (spa)",
        "SPA",
        "IT",
        "NL",
        "CAD (fr)",
        "POR",
        "RU",
        "KOR",
        "TW (ch)",
        "CH",
    ];

    if bytes.len() < base_offset + DISPLAY_VERSION_OFFSET + DISPLAY_VERSION_SIZE {
        return None;
    }

    let mut title = String::new();
    let mut publisher = String::new();
    let mut languages = Vec::new();
    for (idx, label) in LABELS.iter().enumerate() {
        let start = base_offset + idx * ENTRY_SIZE;
        if start + TITLE_SIZE + PUBLISHER_SIZE > bytes.len() {
            break;
        }
        let raw_title = &bytes[start..start + TITLE_SIZE];
        let raw_publisher = &bytes[start + TITLE_SIZE..start + TITLE_SIZE + PUBLISHER_SIZE];
        let title_end = raw_title
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(raw_title.len());
        let publisher_end = raw_publisher
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(raw_publisher.len());
        let current_title = String::from_utf8_lossy(&raw_title[..title_end])
            .trim()
            .to_string();
        let current_publisher = String::from_utf8_lossy(&raw_publisher[..publisher_end])
            .trim()
            .to_string();
        if !current_title.is_empty() {
            if title.is_empty() {
                title = current_title;
                publisher = current_publisher;
            }
            languages.push(*label);
        }
    }

    if languages.is_empty() {
        let lang_mask = u32::from_le_bytes(
            bytes[base_offset + SUPPORTED_LANGUAGE_OFFSET
                ..base_offset + SUPPORTED_LANGUAGE_OFFSET + 4]
                .try_into()
                .ok()?,
        );
        for (idx, label) in LABELS.iter().enumerate() {
            if (lang_mask & (1 << idx)) != 0 {
                languages.push(*label);
            }
        }
    }

    let display_start = base_offset + DISPLAY_VERSION_OFFSET;
    let display_end = bytes[display_start..display_start + DISPLAY_VERSION_SIZE]
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(DISPLAY_VERSION_SIZE);

    Some(ControlInfo {
        title,
        publisher,
        display_version: String::from_utf8_lossy(
            &bytes[display_start..display_start + display_end],
        )
        .trim()
        .to_string(),
        languages,
    })
}

fn parse_nacp_info_heuristic_scan(bytes: &[u8]) -> Option<ControlInfo> {
    for &off in &[0x14200usize, 0x14400usize] {
        if let Some(info) = parse_nacp_info_at(bytes, off) {
            if !info.title.is_empty() && !info.publisher.is_empty() {
                return Some(info);
            }
        }
    }

    let mut off = 0x14000usize;
    while off <= 0x18600usize {
        if let Some(info) = parse_nacp_info_at(bytes, off) {
            if !info.title.is_empty() && !info.publisher.is_empty() {
                return Some(info);
            }
        }
        off += 0x100;
    }

    None
}

fn find_langueblock_offset(bytes: &[u8]) -> Option<usize> {
    for &offset in &[0x14200usize, 0x14400usize] {
        if is_valid_nacp_block(bytes, offset) {
            return Some(offset);
        }
    }
    let mut offset = 0x14000usize;
    while offset <= 0x18600usize {
        if is_valid_nacp_block(bytes, offset) {
            return Some(offset);
        }
        offset += 0x100;
    }
    let mut offset = 0usize;
    while offset + 0x6000 <= bytes.len() {
        if is_valid_nacp_block(bytes, offset) {
            return Some(offset);
        }
        offset += 0x100;
    }
    for &offset in &[0x14200usize, 0x14400usize] {
        if is_valid_nacp_block_fallback(bytes, offset) {
            return Some(offset);
        }
    }
    let mut offset = 0x14000usize;
    while offset <= 0x18600usize {
        if is_valid_nacp_block_fallback(bytes, offset) {
            return Some(offset);
        }
        offset += 0x100;
    }
    let mut offset = 0usize;
    while offset + 0x6000 <= bytes.len() {
        if is_valid_nacp_block_fallback(bytes, offset) {
            return Some(offset);
        }
        offset += 0x100;
    }
    None
}

fn is_valid_nacp_block(bytes: &[u8], offset: usize) -> bool {
    let mut valid_count = 0usize;
    for idx in 0..15usize {
        let base = offset + idx * 0x300;
        if base + 0x300 > bytes.len() {
            continue;
        }
        let title = clean_utf8(&bytes[base..base + 0x200]);
        let editor = clean_utf8(&bytes[base + 0x200..base + 0x300]);
        if is_plausible_title(&title) && is_plausible_publisher(&editor) {
            valid_count += 1;
            if valid_count >= 2 {
                return true;
            }
        }
    }
    false
}

fn is_valid_nacp_block_fallback(bytes: &[u8], offset: usize) -> bool {
    if find_display_version(bytes, offset) == "-" {
        return false;
    }
    for idx in 0..15usize {
        let base = offset + idx * 0x300;
        if base + 0x300 > bytes.len() {
            continue;
        }
        let title = clean_utf8(&bytes[base..base + 0x200]);
        let editor = clean_utf8(&bytes[base + 0x200..base + 0x300]);
        if is_plausible_title(&title) && is_plausible_publisher(&editor) {
            return true;
        }
    }
    false
}

fn find_display_version(bytes: &[u8], offset: usize) -> String {
    let mut candidate_offsets = vec![offset, 0x16900usize.saturating_sub(0x300 * 14)];
    if offset >= 0x300 {
        let mut current = offset;
        for _ in 0..15 {
            current = current.saturating_sub(0x300);
            candidate_offsets.push(current);
        }
    }
    let mut scan = offset;
    while scan + 0x3060 <= 0x18600 && scan + 0x3070 <= bytes.len() {
        candidate_offsets.push(scan);
        scan += 0x100;
    }

    for candidate in candidate_offsets {
        if candidate + 0x3070 > bytes.len() {
            continue;
        }
        let value = clean_utf8(&bytes[candidate + 0x3060..candidate + 0x3070]);
        if is_valid_display_version(&value) {
            return value;
        }
    }
    "-".to_string()
}

fn find_any_display_version(bytes: &[u8]) -> String {
    let mut offset = 0x14000usize;
    while offset <= 0x18600usize {
        let value = find_display_version(bytes, offset);
        if value != "-" {
            return value;
        }
        offset += 0x100;
    }
    if let Some(value) = scan_display_version_ascii(bytes) {
        return value;
    }
    "-".to_string()
}

fn scan_display_version_ascii(bytes: &[u8]) -> Option<String> {
    let mut current = String::new();
    for &byte in bytes {
        let ch = byte as char;
        if ch.is_ascii_digit() || ch == '.' {
            current.push(ch);
            if current.len() > 16 {
                current.clear();
            }
        } else {
            if is_valid_display_version(&current) {
                return Some(current);
            }
            current.clear();
        }
    }
    if is_valid_display_version(&current) {
        return Some(current);
    }
    None
}

fn is_valid_display_version(value: &str) -> bool {
    if value.len() < 4 || value.len() > 16 {
        return false;
    }
    if value.starts_with('v') || value.starts_with('V') {
        return false;
    }
    if !value.chars().all(|ch| ch.is_ascii_digit() || ch == '.') {
        return false;
    }
    value.chars().any(|ch| ch == '.')
        && value.chars().next().is_some_and(|ch| ch.is_ascii_digit())
        && value.chars().last().is_some_and(|ch| ch.is_ascii_digit())
}

fn collect_supported_languages(bytes: &[u8], offset: usize) -> Vec<&'static str> {
    let labels = [
        "US (eng)",
        "UK (eng)",
        "JP",
        "FR",
        "DE",
        "LAT (spa)",
        "SPA",
        "IT",
        "DU",
        "CAD (fr)",
        "POR",
        "RU",
        "KOR",
        "TW (ch)",
        "CH",
    ];
    if offset + 0x3030 <= bytes.len() {
        if let Ok(mask_bytes) = bytes[offset + 0x302C..offset + 0x3030].try_into() {
            let mask = u32::from_le_bytes(mask_bytes);
            let mut out = Vec::new();
            for (idx, label) in labels.iter().enumerate() {
                if (mask & (1 << idx)) != 0 {
                    out.push(*label);
                }
            }
            if !out.is_empty() {
                return out;
            }
        }
    }
    let mut out = Vec::new();
    for (idx, label) in labels.iter().enumerate() {
        let base = offset + idx * 0x300;
        if base + 0x200 > bytes.len() {
            continue;
        }
        let title = clean_utf8(&bytes[base..base + 0x200]);
        if is_plausible_title(&title) {
            out.push(*label);
        }
    }
    out
}

fn clean_utf8(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end])
        .replace(['/', '\\'], " ")
        .trim()
        .to_string()
}

fn is_plausible_title(value: &str) -> bool {
    if value.len() < 1 || value.len() > 200 {
        return false;
    }
    if value.contains('\u{FFFD}') {
        return false;
    }
    if value.chars().any(|ch| ch.is_control()) {
        return false;
    }
    value.chars().any(|ch| ch.is_alphabetic())
}

fn is_plausible_publisher(value: &str) -> bool {
    if value.len() < 2 || value.len() > 200 {
        return false;
    }
    if value.contains('\u{FFFD}') {
        return false;
    }
    if value.chars().any(|ch| ch.is_control()) {
        return false;
    }
    value.chars().any(|ch| ch.is_alphabetic())
}

fn pfs0_candidate_offsets(section: &[u8]) -> Vec<usize> {
    let mut out = vec![0usize];
    let scan_len = section.len().min(1024 * 1024);
    if scan_len >= 4 {
        for i in 0..=(scan_len - 4) {
            if &section[i..i + 4] == b"PFS0" {
                out.push(i);
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn aes_ctr_transform_in_place(
    key: &[u8; 16],
    nonce8: &[u8; 8],
    file_offset: u64,
    big_endian_counter: bool,
    data: &mut [u8],
) {
    let Ok(cipher) = Aes128::new_from_slice(key) else {
        return;
    };
    let mut cached_block_index = u64::MAX;
    let mut cached_keystream = [0u8; 16];
    for (i, byte) in data.iter_mut().enumerate() {
        let abs = file_offset + i as u64;
        let block_index = abs / 16;
        let byte_in_block = (abs % 16) as usize;
        if block_index != cached_block_index {
            let mut ctr = [0u8; 16];
            ctr[..8].copy_from_slice(nonce8);
            if big_endian_counter {
                ctr[8..].copy_from_slice(&block_index.to_be_bytes());
            } else {
                ctr[8..].copy_from_slice(&block_index.to_le_bytes());
            }
            let mut block = aes::Block::from(ctr);
            cipher.encrypt_block(&mut block);
            cached_keystream.copy_from_slice(&block);
            cached_block_index = block_index;
        }
        *byte ^= cached_keystream[byte_in_block];
    }
}

fn format_sdk_version(sdk_version: u32) -> String {
    let b = sdk_version.to_le_bytes();
    format!("{}.{}.{}.{}", b[3], b[2], b[1], b[0])
}

fn python_size(bytes: u64) -> String {
    if bytes > 1024 * 1024 * 1024 {
        format!("{:.2}GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes > 1024 * 1024 {
        format!("{:.2}MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes > 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{}B", bytes)
    }
}

fn python_fw_range_kg(keygeneration: u8) -> &'static str {
    match keygeneration {
        0 => "(1.0.0)",
        1 => "(2.0.0 - 2.3.0)",
        2 => "(3.0.0)",
        3 => "(3.0.1 - 3.0.2)",
        4 => "(4.0.0 - 4.1.0)",
        5 => "(5.0.0 - 5.1.0)",
        6 => "(6.0.0 - 6.1.0)",
        7 => "(6.2.0)",
        8 => "(7.0.0 - 8.0.1)",
        9 => "(8.1.0)",
        10 => "(9.0.0 - 9.0.1)",
        11 => "(9.1.0 - 12.0.3)",
        12 => "(12.1.0)",
        13 => "(>= 13.0.0)",
        _ => "UNKNOWN",
    }
}

fn python_fw_range_rsv(rsv: u32) -> String {
    if rsv >= 3 * 67_108_864 {
        let first = rsv / 67_108_864;
        let rem = rsv % 67_108_864;
        let second = rem / 1_048_576;
        let rem = rem % 1_048_576;
        let third = rem / 65_536;
        let fourth = rem % 65_536;
        if fourth > 0 {
            format!("({}.{}.{}-{})", first, second, third, fourth)
        } else {
            format!("({}.{}.{})", first, second, third)
        }
    } else if rsv >= 65_536 {
        let second = rsv / 65_536;
        let fourth = rsv % 65_536;
        if fourth > 0 {
            format!("(2.{}.0-{})", second, fourth)
        } else {
            format!("(2.{}.0)", second)
        }
    } else if rsv > 0 {
        let fourth = rsv % 65_536;
        if fourth > 0 {
            format!("(1.0.0-{})", fourth)
        } else {
            "(1.0.0)".to_string()
        }
    } else {
        "(1.0.0)".to_string()
    }
}

fn python_min_rsv(keygeneration: u8, rsv: u32) -> u32 {
    crate::formats::types::get_min_rsv(keygeneration, rsv)
}

fn python_cnmt_name(title_type: TitleType) -> &'static str {
    match title_type {
        TitleType::Application => "Application",
        TitleType::Patch => "Patch",
        TitleType::AddOnContent => "AddOnContent",
        TitleType::Delta => "Delta",
        TitleType::SystemProgram => "SystemProgram",
        TitleType::SystemData => "SystemData",
        TitleType::SystemUpdate => "SystemUpdate",
        TitleType::BootImagePackage => "BootImagePackage",
        TitleType::BootImagePackageSafe => "BootImagePackageSafe",
    }
}

fn python_content_type_label(title_type: TitleType) -> &'static str {
    match title_type {
        TitleType::Patch => "Update",
        TitleType::AddOnContent => "DLC",
        _ => "Game or Application",
    }
}

fn python_nca_line(entry: &ContentEntryReport) -> String {
    let label = match entry.ncatype {
        0 => "Meta: ",
        1 => "Program: ",
        2 => "Data: ",
        3 => "Control: ",
        4 => "HtmlDoc: ",
        5 => "LegalInf: ",
        6 => "Delta: ",
        _ => "Data: ",
    };
    if label == "Meta: " {
        format!(
            "- {}\t{}\tSize: {}",
            label,
            entry.name,
            python_size(entry.size)
        )
    } else {
        format!(
            "- {}\t{}\t\tSize: {}",
            label,
            entry.name,
            python_size(entry.size)
        )
    }
}

fn python_xml_size(title: &TitleReport) -> u64 {
    build_python_xml_string(title).len() as u64
}

fn build_python_xml_string(title: &TitleReport) -> String {
    let title_type = python_cnmt_name(title.title_type);
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    xml.push_str("<ContentMeta>\n");
    xml.push_str(&format!("  <Type>{}</Type>\n", title_type));
    xml.push_str(&format!("  <Id>0x{:016x}</Id>\n", title.title_id));
    xml.push_str(&format!("  <Version>{}</Version>\n", title.version));
    xml.push_str("  <RequiredDownloadSystemVersion>0</RequiredDownloadSystemVersion>\n");
    for entry in &title.content_entries {
        let kind = match entry.ncatype {
            0 => "Meta",
            1 => "Program",
            2 => "Data",
            3 => "Control",
            4 => "HtmlDocument",
            5 => "LegalInformation",
            6 => "DeltaFragment",
            _ => "Data",
        };
        xml.push_str("  <Content>\n");
        xml.push_str(&format!("    <Type>{}</Type>\n", kind));
        xml.push_str(&format!(
            "    <Id>{}</Id>\n",
            entry.name.trim_end_matches(".nca").trim_end_matches(".ncz")
        ));
        xml.push_str(&format!("    <Size>{}</Size>\n", entry.size));
        xml.push_str(
            "    <Hash>0000000000000000000000000000000000000000000000000000000000000000</Hash>\n",
        );
        xml.push_str(&format!(
            "    <KeyGeneration>{}</KeyGeneration>\n",
            title.key_generation
        ));
        xml.push_str("  </Content>\n");
    }
    xml.push_str(
        "  <Digest>0000000000000000000000000000000000000000000000000000000000000000</Digest>\n",
    );
    xml.push_str(&format!(
        "  <KeyGeneration>{}</KeyGeneration>\n",
        title.key_generation
    ));
    xml.push_str(&format!(
        "  <RequiredSystemVersion>{}</RequiredSystemVersion>\n",
        title.required_system_version
    ));
    xml.push_str(&format!(
        "  <OriginalId>0x{:016x}</OriginalId>\n",
        title.base_id
    ));
    xml.push_str("</ContentMeta>");
    xml
}

fn infer_title_type(title_id: u64) -> TitleType {
    match title_id & 0xFFF {
        0x800 => TitleType::Patch,
        0x000 => TitleType::Application,
        _ => TitleType::AddOnContent,
    }
}

fn fallback_patch_display_version(version: u32) -> String {
    let patch_number = version / 65_536;
    format!("1.{:02}", patch_number + 1)
}

fn title_sort_rank(title: &TitleReport) -> u8 {
    match title.title_type {
        TitleType::Application => 0,
        TitleType::Patch => 1,
        TitleType::AddOnContent => 2,
        _ => 3,
    }
}

fn dlc_number(title_id: u64) -> u64 {
    title_id & 0xFFF
}

fn python_spacing(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let has_non_ascii = trimmed.chars().any(|ch| !ch.is_ascii());
    let has_ascii_alpha = trimmed.chars().any(|ch| ch.is_ascii_alphabetic());
    if has_non_ascii && !has_ascii_alpha {
        trimmed
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .map(|ch| ch.to_string())
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        trimmed.to_string()
    }
}

fn push_line(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}

fn lower_tid(tid: u64) -> String {
    format!("{:016x}", tid)
}

fn ext(path: &str) -> String {
    Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}
