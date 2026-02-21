use crate::error::{NscbError, Result};

/// Parse a display title from NACP bytes.
///
/// NACP stores 16 language entries, each 0x300 bytes:
/// - title: 0x200 bytes
/// - publisher: 0x100 bytes
///
/// We return the first non-empty title entry.
pub fn parse_title(data: &[u8]) -> Result<String> {
    const LANG_ENTRIES: usize = 16;
    const ENTRY_SIZE: usize = 0x300;
    const TITLE_SIZE: usize = 0x200;

    if data.len() < ENTRY_SIZE {
        return Err(NscbError::InvalidData("NACP too short".to_string()));
    }

    for i in 0..LANG_ENTRIES {
        let start = i * ENTRY_SIZE;
        if start + TITLE_SIZE > data.len() {
            break;
        }
        let raw = &data[start..start + TITLE_SIZE];
        let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
        let s = String::from_utf8_lossy(&raw[..end]).trim().to_string();
        if is_plausible_title(&s) {
            return Ok(s);
        }
    }

    Err(NscbError::InvalidData(
        "No non-empty title in NACP".to_string(),
    ))
}

/// Parse title from a NACP-style language block at a known base offset.
pub fn parse_title_block_at(data: &[u8], base_offset: usize) -> Option<String> {
    const LANG_ENTRIES: usize = 15;
    const ENTRY_SIZE: usize = 0x300;
    const TITLE_SIZE: usize = 0x200;
    const PUBLISHER_SIZE: usize = 0x100;

    let mut first_valid: Option<String> = None;
    let mut valid_count = 0usize;
    for i in 0..LANG_ENTRIES {
        let start = base_offset + i * ENTRY_SIZE;
        if start + TITLE_SIZE + PUBLISHER_SIZE > data.len() {
            break;
        }
        let title_raw = &data[start..start + TITLE_SIZE];
        let pub_raw = &data[start + TITLE_SIZE..start + TITLE_SIZE + PUBLISHER_SIZE];

        let t_end = title_raw.iter().position(|b| *b == 0).unwrap_or(title_raw.len());
        let p_end = pub_raw.iter().position(|b| *b == 0).unwrap_or(pub_raw.len());
        let title = String::from_utf8_lossy(&title_raw[..t_end]).trim().to_string();
        let publisher = String::from_utf8_lossy(&pub_raw[..p_end]).trim().to_string();
        if is_plausible_title(&title) && is_plausible_publisher(&publisher) {
            valid_count += 1;
            if first_valid.is_none() {
                first_valid = Some(title);
            }
        }
    }
    if valid_count >= 2 {
        first_valid
    } else {
        None
    }
}

fn is_plausible_title(s: &str) -> bool {
    if s.len() < 3 || s.len() > 200 {
        return false;
    }
    if s.contains('\u{FFFD}') {
        return false;
    }
    if !s.chars().any(|c| c.is_alphabetic()) {
        return false;
    }
    if s.chars().any(|c| c.is_control()) {
        return false;
    }
    true
}

fn is_plausible_publisher(s: &str) -> bool {
    if s.len() < 2 || s.len() > 200 {
        return false;
    }
    if s.contains('\u{FFFD}') {
        return false;
    }
    if !s.chars().any(|c| c.is_alphabetic()) {
        return false;
    }
    if s.chars().any(|c| c.is_control()) {
        return false;
    }
    true
}

/// Heuristic scanner similar to squirrel's CONTROL title probing.
pub fn parse_title_heuristic_scan(data: &[u8]) -> Option<String> {
    for &off in &[0x14200usize, 0x14400usize] {
        if let Some(t) = parse_title_block_at(data, off) {
            return Some(t);
        }
    }

    let mut off = 0x14000usize;
    while off <= 0x18600usize {
        if let Some(t) = parse_title_block_at(data, off) {
            return Some(t);
        }
        off += 0x100;
    }
    None
}
