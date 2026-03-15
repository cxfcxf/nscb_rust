use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, USER_AGENT};
use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{NscbError, Result};

const DEFAULT_SOURCE_URL: &str =
    "https://raw.githubusercontent.com/blawar/titledb/master/US.en.json";
const RAW_CACHE_FILE: &str = "nutdb.raw.json";
const INDEX_CACHE_FILE: &str = "nutdb.index.json";
const META_CACHE_FILE: &str = "nutdb.meta.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshStatus {
    Downloaded,
    NotModified,
    UsedCached,
}

impl RefreshStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            RefreshStatus::Downloaded => "downloaded",
            RefreshStatus::NotModified => "not-modified",
            RefreshStatus::UsedCached => "used-cached",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshOutcome {
    pub status: RefreshStatus,
    pub indexed_titles: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NutdbTitle {
    pub name: Option<String>,
    pub publisher: Option<String>,
    #[serde(default)]
    pub languages: Vec<String>,
    pub version: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NutdbIndex {
    pub source_url: String,
    #[serde(default)]
    pub titles: HashMap<String, NutdbTitle>,
}

impl NutdbIndex {
    pub fn len(&self) -> usize {
        self.titles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.titles.is_empty()
    }

    pub fn lookup(&self, title_id: &str) -> Option<&NutdbTitle> {
        let title_id = normalize_title_id(title_id)?;
        self.titles.get(&title_id)
    }

    pub fn languages_for(&self, title_id: &str) -> Vec<String> {
        let base_id = base_title_id(title_id);
        self.lookup(&base_id)
            .map(|title| title.languages.clone())
            .unwrap_or_default()
    }

    pub fn display_name_for(&self, title_id: &str) -> Option<String> {
        let title_id = normalize_title_id(title_id)?;
        if title_id.ends_with("000") {
            return self.lookup(&title_id).and_then(|t| t.name.clone());
        }

        if title_id.ends_with("800") {
            return self
                .lookup(&title_id)
                .and_then(|t| t.name.clone())
                .or_else(|| {
                    let base_id = base_title_id(&title_id);
                    self.lookup(&base_id).and_then(|t| t.name.clone())
                });
        }

        let base_id = base_title_id(&title_id);
        let base_name = self.lookup(&base_id).and_then(|t| t.name.clone());
        let dlc_name = self.lookup(&title_id).and_then(|t| t.name.clone());
        match (base_name, dlc_name) {
            (Some(base), Some(dlc)) if base != dlc => Some(format!("{base} [{dlc}]")),
            (_, Some(dlc)) => Some(dlc),
            (Some(base), None) => Some(format!("{base} [DLC {}]", dlc_number(&title_id))),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CacheMetadata {
    source_url: String,
    etag: Option<String>,
    last_modified: Option<String>,
    raw_sha256: String,
}

#[derive(Debug, Clone)]
pub struct NutdbStore {
    cache_dir: PathBuf,
    source_url: String,
}

impl NutdbStore {
    pub fn new(cache_dir: Option<&str>, source_url: Option<&str>) -> Self {
        let cache_dir = cache_dir
            .map(PathBuf::from)
            .unwrap_or_else(default_cache_dir);
        let source_url = source_url.unwrap_or(DEFAULT_SOURCE_URL).to_string();
        Self {
            cache_dir,
            source_url,
        }
    }

    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    pub fn source_url(&self) -> &str {
        &self.source_url
    }

    pub fn ensure_index(&self) -> Result<NutdbIndex> {
        if let Ok(index) = self.load_cached_index() {
            if self
                .read_metadata()
                .map(|meta| meta.source_url == self.source_url)
                .unwrap_or(true)
            {
                return Ok(index);
            }
        }
        self.refresh()?;
        self.load_cached_index()
    }

    pub fn try_load_cached_index(&self) -> Result<Option<NutdbIndex>> {
        match self.load_cached_index() {
            Ok(index) => Ok(Some(index)),
            Err(NscbError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    pub fn refresh(&self) -> Result<RefreshOutcome> {
        fs::create_dir_all(&self.cache_dir)?;

        let cached_index = self.try_load_cached_index()?;
        let cached_meta = self.read_metadata().ok();
        let client = build_http_client()?;

        let mut request = client
            .get(&self.source_url)
            .header(USER_AGENT, "nscb-rust/0.1");
        if let Some(meta) = cached_meta
            .as_ref()
            .filter(|m| m.source_url == self.source_url)
        {
            if let Some(etag) = &meta.etag {
                request = request.header(IF_NONE_MATCH, etag);
            }
            if let Some(last_modified) = &meta.last_modified {
                request = request.header(IF_MODIFIED_SINCE, last_modified);
            }
        }

        let response = match request.send() {
            Ok(response) => response,
            Err(err) => {
                if let Some(index) = cached_index {
                    return Ok(RefreshOutcome {
                        status: RefreshStatus::UsedCached,
                        indexed_titles: index.len(),
                    });
                }
                return Err(NscbError::Http(err.to_string()));
            }
        };

        if response.status().as_u16() == 304 {
            let index = self.load_cached_index()?;
            return Ok(RefreshOutcome {
                status: RefreshStatus::NotModified,
                indexed_titles: index.len(),
            });
        }

        if !response.status().is_success() {
            if let Some(index) = cached_index {
                return Ok(RefreshOutcome {
                    status: RefreshStatus::UsedCached,
                    indexed_titles: index.len(),
                });
            }
            return Err(NscbError::Http(format!(
                "NUTDB request failed with status {}",
                response.status()
            )));
        }

        let etag = header_value(response.headers(), ETAG);
        let last_modified = header_value(response.headers(), LAST_MODIFIED);

        let raw_tmp_path = self.cache_dir.join(format!("{RAW_CACHE_FILE}.tmp"));
        let index_tmp_path = self.cache_dir.join(format!("{INDEX_CACHE_FILE}.tmp"));
        let meta_tmp_path = self.cache_dir.join(format!("{META_CACHE_FILE}.tmp"));
        let raw_path = self.cache_dir.join(RAW_CACHE_FILE);
        let index_path = self.cache_dir.join(INDEX_CACHE_FILE);
        let meta_path = self.cache_dir.join(META_CACHE_FILE);

        let (hash_hex, _) = download_raw_json(response, &raw_tmp_path)?;
        let index = build_index_from_path(&raw_tmp_path, self.source_url.clone())?;
        write_json_file(&index_tmp_path, &index)?;
        write_json_file(
            &meta_tmp_path,
            &CacheMetadata {
                source_url: self.source_url.clone(),
                etag,
                last_modified,
                raw_sha256: hash_hex,
            },
        )?;

        fs::rename(&raw_tmp_path, &raw_path)?;
        fs::rename(&index_tmp_path, &index_path)?;
        fs::rename(&meta_tmp_path, &meta_path)?;

        Ok(RefreshOutcome {
            status: RefreshStatus::Downloaded,
            indexed_titles: index.len(),
        })
    }

    fn load_cached_index(&self) -> Result<NutdbIndex> {
        let path = self.cache_dir.join(INDEX_CACHE_FILE);
        let reader = BufReader::new(File::open(path)?);
        serde_json::from_reader(reader).map_err(|err| NscbError::Json(err.to_string()))
    }

    fn read_metadata(&self) -> Result<CacheMetadata> {
        let path = self.cache_dir.join(META_CACHE_FILE);
        let reader = BufReader::new(File::open(path)?);
        serde_json::from_reader(reader).map_err(|err| NscbError::Json(err.to_string()))
    }
}

#[derive(Debug, Deserialize)]
struct RawTitleEntry {
    #[serde(default, deserialize_with = "deserialize_opt_string")]
    id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_opt_string")]
    name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_opt_string")]
    publisher: Option<String>,
    #[serde(default, deserialize_with = "deserialize_languages")]
    languages: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_opt_u64")]
    version: Option<u64>,
}

impl RawTitleEntry {
    fn into_title(self) -> Option<(String, NutdbTitle)> {
        let title_id = normalize_title_id(self.id.as_deref()?)?;
        Some((
            title_id,
            NutdbTitle {
                name: self.name,
                publisher: self.publisher,
                languages: self.languages,
                version: self.version,
            },
        ))
    }
}

struct TitlesVisitor;

impl<'de> Visitor<'de> for TitlesVisitor {
    type Value = HashMap<String, NutdbTitle>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a NUTDB JSON object")
    }

    fn visit_map<M>(self, mut access: M) -> std::result::Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut titles = HashMap::new();
        while let Some((_ignored, entry)) = access.next_entry::<IgnoredAny, RawTitleEntry>()? {
            if let Some((title_id, title)) = entry.into_title() {
                titles.insert(title_id, title);
            }
        }
        Ok(titles)
    }
}

fn build_index_from_path(path: &Path, source_url: String) -> Result<NutdbIndex> {
    let reader = BufReader::new(File::open(path)?);
    build_index_from_reader(reader, source_url)
}

fn build_index_from_reader<R: Read>(reader: R, source_url: String) -> Result<NutdbIndex> {
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    let titles = deserializer
        .deserialize_map(TitlesVisitor)
        .map_err(|err| NscbError::Json(err.to_string()))?;
    Ok(NutdbIndex { source_url, titles })
}

fn build_http_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|err| NscbError::Http(err.to_string()))
}

fn download_raw_json(
    mut response: reqwest::blocking::Response,
    destination: &Path,
) -> Result<(String, u64)> {
    let mut writer = BufWriter::new(File::create(destination)?);
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let read = response
            .read(&mut buffer)
            .map_err(|err| NscbError::Http(err.to_string()))?;
        if read == 0 {
            break;
        }
        writer.write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
        total += read as u64;
    }
    writer.flush()?;
    Ok((hex::encode(hasher.finalize()), total))
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let writer = BufWriter::new(File::create(path)?);
    serde_json::to_writer(writer, value).map_err(|err| NscbError::Json(err.to_string()))
}

fn header_value(
    headers: &reqwest::header::HeaderMap,
    name: reqwest::header::HeaderName,
) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
}

fn deserialize_opt_string<'de, D>(deserializer: D) -> std::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(match value {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(text)) => normalize_optional_text(text),
        Some(other) => normalize_optional_text(other.to_string()),
    })
}

fn deserialize_opt_u64<'de, D>(deserializer: D) -> std::result::Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(match value {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Number(number)) => number
            .as_u64()
            .or_else(|| number.as_i64().map(|v| v.max(0) as u64)),
        Some(serde_json::Value::String(text)) => text.trim().parse::<u64>().ok(),
        Some(_) => None,
    })
}

fn deserialize_languages<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    let mut languages = Vec::new();
    match value {
        None | Some(serde_json::Value::Null) => {}
        Some(serde_json::Value::String(text)) => {
            for item in text.split(',') {
                if let Some(item) = normalize_optional_text(item.to_string()) {
                    languages.push(item);
                }
            }
        }
        Some(serde_json::Value::Array(items)) => {
            for item in items {
                if let Some(item) =
                    normalize_optional_text(item.to_string().trim_matches('"').to_string())
                {
                    languages.push(item);
                }
            }
        }
        Some(_) => {}
    }
    Ok(languages)
}

fn normalize_optional_text(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("none") {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub fn normalize_title_id(title_id: &str) -> Option<String> {
    let trimmed = title_id.trim();
    if trimmed.len() != 16 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(trimmed.to_ascii_uppercase())
}

pub fn base_title_id(title_id: &str) -> String {
    let title_id =
        normalize_title_id(title_id).unwrap_or_else(|| title_id.trim().to_ascii_uppercase());
    if title_id.ends_with("000") {
        return title_id;
    }
    if title_id.ends_with("800") && title_id.len() == 16 {
        let mut chars: Vec<char> = title_id.chars().collect();
        chars[13] = '0';
        chars[14] = '0';
        chars[15] = '0';
        return chars.into_iter().collect();
    }
    if title_id.len() == 16 {
        let mut chars: Vec<char> = title_id.chars().collect();
        if let Some(nibble) = chars.get(12).and_then(|c| c.to_digit(16)) {
            let adjusted = nibble.saturating_sub(1);
            chars[12] = char::from_digit(adjusted, 16).unwrap().to_ascii_uppercase();
            chars[13] = '0';
            chars[14] = '0';
            chars[15] = '0';
            return chars.into_iter().collect();
        }
    }
    title_id
}

pub fn dlc_number(title_id: &str) -> u16 {
    let title_id =
        normalize_title_id(title_id).unwrap_or_else(|| title_id.trim().to_ascii_uppercase());
    u16::from_str_radix(&title_id[13..], 16).unwrap_or(0)
}

fn default_cache_dir() -> PathBuf {
    if let Ok(path) = std::env::var("NSCB_NUTDB_CACHE_DIR") {
        return PathBuf::from(path);
    }
    if let Ok(path) = std::env::var("XDG_CACHE_HOME") {
        return PathBuf::from(path).join("nscb").join("nutdb");
    }
    if let Ok(path) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(path).join("nscb").join("nutdb");
    }
    if let Ok(path) = std::env::var("HOME") {
        return PathBuf::from(path)
            .join(".cache")
            .join("nscb")
            .join("nutdb");
    }
    if let Ok(path) = std::env::var("USERPROFILE") {
        return PathBuf::from(path)
            .join(".cache")
            .join("nscb")
            .join("nutdb");
    }
    PathBuf::from(".nscb").join("cache").join("nutdb")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    use tempfile::tempdir;

    #[test]
    fn base_title_id_matches_python_rules() {
        assert_eq!(base_title_id("0100F8F0000A2000"), "0100F8F0000A2000");
        assert_eq!(base_title_id("0100F8F0000A2800"), "0100F8F0000A2000");
        assert_eq!(base_title_id("0100F8F0000A3401"), "0100F8F0000A2000");
    }

    #[test]
    fn builds_compact_index_from_streamed_json() {
        let json = r#"{
            "0": {"id":"0100F8F0000A2000","name":"Base Game","publisher":"Studio","languages":["en","fr"],"version":"0"},
            "1": {"id":"0100F8F0000A3401","name":"Expansion Pack","publisher":"Studio"},
            "2": {"id":"invalid","name":"Skip Me"}
        }"#;

        let index = build_index_from_reader(
            json.as_bytes(),
            "http://example.test/nutdb.json".to_string(),
        )
        .expect("index builds");

        assert_eq!(index.len(), 2);
        assert_eq!(
            index.display_name_for("0100F8F0000A3401").as_deref(),
            Some("Base Game [Expansion Pack]")
        );
        assert_eq!(index.languages_for("0100F8F0000A3401"), vec!["en", "fr"]);
    }

    #[test]
    fn refresh_uses_conditional_http_and_keeps_local_index() {
        let dir = tempdir().expect("tempdir");
        let etag = "\"etag-123\"";
        let body = r#"{
            "0": {"id":"0100F8F0000A2000","name":"Base Game","publisher":"Studio","languages":["en"],"version":"0"}
        }"#;
        let request_count = Arc::new(Mutex::new(0usize));
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let addr = listener.local_addr().expect("local addr");
        let requests = Arc::clone(&request_count);
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("accept");
                let mut buffer = [0u8; 8192];
                let read = stream.read(&mut buffer).expect("read request");
                let request = String::from_utf8_lossy(&buffer[..read]).to_lowercase();
                let mut count = requests.lock().expect("lock");
                *count += 1;
                drop(count);

                if request.contains("if-none-match: \"etag-123\"") {
                    let response = "HTTP/1.1 304 Not Modified\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                    stream.write_all(response.as_bytes()).expect("write 304");
                } else {
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nETag: {etag}\r\nLast-Modified: Tue, 01 Jan 2030 00:00:00 GMT\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    stream.write_all(response.as_bytes()).expect("write 200");
                }
            }
        });

        let url = format!("http://{addr}/nutdb.json");
        let store = NutdbStore::new(Some(dir.path().to_string_lossy().as_ref()), Some(&url));

        let first = store.refresh().expect("first refresh");
        assert_eq!(first.status, RefreshStatus::Downloaded);
        assert_eq!(first.indexed_titles, 1);

        let second = store.refresh().expect("second refresh");
        assert_eq!(second.status, RefreshStatus::NotModified);
        assert_eq!(second.indexed_titles, 1);

        let index = store.ensure_index().expect("cached index");
        assert_eq!(
            index.display_name_for("0100F8F0000A2000").as_deref(),
            Some("Base Game")
        );

        server.join().expect("server join");
        assert_eq!(*request_count.lock().expect("lock"), 2);
    }
}
