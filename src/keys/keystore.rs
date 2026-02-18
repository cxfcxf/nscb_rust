use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::aes_ecb;
use crate::error::{NscbError, Result};
use crate::keys::derivation;

/// Maximum number of master key revisions to derive keys for.
const MAX_KEY_REVISION: usize = 32;

/// Holds all loaded and derived cryptographic keys.
pub struct KeyStore {
    /// Raw keys from prod.keys: name → bytes
    raw: HashMap<String, Vec<u8>>,
    /// Pre-derived title KEKs by master key revision
    title_keks: Vec<Option<[u8; 16]>>,
    /// Pre-derived key area keys: [revision][type] where type: 0=app, 1=ocean, 2=system
    key_area_keys: Vec<[Option<[u8; 16]>; 3]>,
}

impl KeyStore {
    /// Load keys from a file and derive all needed keys.
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path).map_err(|e| {
            NscbError::KeyNotFound(format!("Cannot read key file {}: {e}", path.display()))
        })?;
        Self::from_string(&content)
    }

    /// Load keys from string content.
    pub fn from_string(content: &str) -> Result<Self> {
        let mut raw = HashMap::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            if let Some((name, value)) = line.split_once('=') {
                let name = name.trim().to_lowercase();
                let value = value.trim();
                if let Ok(bytes) = hex::decode(value) {
                    raw.insert(name, bytes);
                }
            }
        }

        let mut store = Self {
            raw,
            title_keks: vec![None; MAX_KEY_REVISION],
            key_area_keys: vec![[None; 3]; MAX_KEY_REVISION],
        };

        store.derive_keys();
        Ok(store)
    }

    /// Try to find and load keys from standard locations.
    pub fn from_default_locations(explicit_path: Option<&str>) -> Result<Self> {
        let candidates: Vec<PathBuf> = if let Some(p) = explicit_path {
            vec![PathBuf::from(p)]
        } else {
            let mut paths = Vec::new();

            // Current directory first
            paths.push(PathBuf::from("prod.keys"));
            paths.push(PathBuf::from("keys.txt"));

            // Check NSCB_KEYS env var
            if let Ok(env_path) = std::env::var("NSCB_KEYS") {
                paths.push(PathBuf::from(env_path));
            }

            // ~/.switch/prod.keys
            if let Some(home) = dirs_home() {
                paths.push(home.join(".switch").join("prod.keys"));
                paths.push(home.join(".config").join("nscb").join("prod.keys"));
            }

            // Same directory as executable
            if let Ok(exe) = std::env::current_exe() {
                if let Some(dir) = exe.parent() {
                    paths.push(dir.join("prod.keys"));
                    paths.push(dir.join("keys.txt"));
                }
            }

            paths
        };

        for path in &candidates {
            if path.exists() {
                return Self::from_file(path);
            }
        }

        Err(NscbError::KeyNotFound(
            "No prod.keys found. Place it in ~/.switch/prod.keys or use --keys <path>".into(),
        ))
    }

    /// Derive all title KEKs and key area keys from master keys.
    fn derive_keys(&mut self) {
        let aes_kek_gen = self.get_raw_16("aes_kek_generation_source");
        let aes_key_gen = self.get_raw_16("aes_key_generation_source");
        let titlekek_src = self.get_raw_16("titlekek_source");
        let kak_app_src = self.get_raw_16("key_area_key_application_source");
        let kak_ocean_src = self.get_raw_16("key_area_key_ocean_source");
        let kak_system_src = self.get_raw_16("key_area_key_system_source");

        for i in 0..MAX_KEY_REVISION {
            let mk_name = format!("master_key_{:02x}", i);
            let mk = match self.get_raw_16(&mk_name) {
                Some(k) => k,
                None => continue,
            };

            // Derive title KEK
            if let (Some(src), Some(kek_gen), Some(key_gen)) =
                (titlekek_src, aes_kek_gen, aes_key_gen)
            {
                if let Ok(kek) = derivation::derive_title_kek(&mk, &src, &kek_gen, &key_gen) {
                    self.title_keks[i] = Some(kek);
                }
            }

            // Derive key area keys
            if let (Some(kek_gen), Some(key_gen)) = (aes_kek_gen, aes_key_gen) {
                if let Some(src) = kak_app_src {
                    if let Ok(k) = derivation::derive_key_area_key(&mk, &src, &kek_gen, &key_gen) {
                        self.key_area_keys[i][0] = Some(k);
                    }
                }
                if let Some(src) = kak_ocean_src {
                    if let Ok(k) = derivation::derive_key_area_key(&mk, &src, &kek_gen, &key_gen) {
                        self.key_area_keys[i][1] = Some(k);
                    }
                }
                if let Some(src) = kak_system_src {
                    if let Ok(k) = derivation::derive_key_area_key(&mk, &src, &kek_gen, &key_gen) {
                        self.key_area_keys[i][2] = Some(k);
                    }
                }
            }
        }
    }

    /// Get a raw 16-byte key by name.
    fn get_raw_16(&self, name: &str) -> Option<[u8; 16]> {
        self.raw.get(name).and_then(|v| {
            if v.len() == 16 {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(v);
                Some(arr)
            } else {
                None
            }
        })
    }

    /// Get the 32-byte NCA header key.
    pub fn header_key(&self) -> Result<[u8; 32]> {
        let v = self
            .raw
            .get("header_key")
            .ok_or_else(|| NscbError::KeyNotFound("header_key not found in prod.keys".into()))?;
        if v.len() != 32 {
            return Err(NscbError::KeyNotFound(format!(
                "header_key has wrong size: {} (expected 32)",
                v.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(v);
        Ok(arr)
    }

    /// Get master key for a given revision.
    pub fn master_key(&self, revision: u8) -> Result<[u8; 16]> {
        let name = format!("master_key_{:02x}", revision);
        self.get_raw_16(&name)
            .ok_or_else(|| NscbError::KeyNotFound(format!("master_key_{:02x} not found", revision)))
    }

    /// Get pre-derived title KEK for a given revision.
    pub fn title_kek(&self, revision: u8) -> Result<[u8; 16]> {
        self.title_keks
            .get(revision as usize)
            .and_then(|k| *k)
            .ok_or_else(|| {
                NscbError::KeyNotFound(format!("title_kek for revision {} not derived", revision))
            })
    }

    /// Get pre-derived key area key.
    /// key_type: 0=application, 1=ocean, 2=system
    pub fn key_area_key(&self, revision: u8, key_type: u8) -> Result<[u8; 16]> {
        let type_names = ["application", "ocean", "system"];
        self.key_area_keys
            .get(revision as usize)
            .and_then(|arr| arr.get(key_type as usize))
            .and_then(|k| *k)
            .ok_or_else(|| {
                let tn = type_names.get(key_type as usize).unwrap_or(&"unknown");
                NscbError::KeyNotFound(format!(
                    "key_area_key_{} for revision {} not derived",
                    tn, revision
                ))
            })
    }

    /// Decrypt a title key using the title KEK for the given master key revision.
    pub fn decrypt_title_key(
        &self,
        encrypted: &[u8; 16],
        master_key_revision: u8,
    ) -> Result<[u8; 16]> {
        let kek = self.title_kek(master_key_revision)?;
        derivation::decrypt_title_key(encrypted, &kek)
    }

    /// Decrypt an NCA key area entry using the appropriate key area key.
    pub fn decrypt_key_area_entry(
        &self,
        encrypted: &[u8; 16],
        master_key_revision: u8,
        key_type: u8,
    ) -> Result<[u8; 16]> {
        let kak = self.key_area_key(master_key_revision, key_type)?;
        aes_ecb::decrypt_block(&kak, encrypted)
    }

    /// Check if a specific key exists.
    pub fn has_key(&self, name: &str) -> bool {
        self.raw.contains_key(name)
    }
}

/// Get user home directory.
fn dirs_home() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| std::env::var("USERPROFILE").ok().map(PathBuf::from))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_keys_file() {
        let content = r#"
# Nintendo Switch prod.keys
header_key = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
master_key_00 = 0123456789abcdef0123456789abcdef

; comment
bad line without equals

aes_kek_generation_source = 0123456789abcdef0123456789abcdef
"#;
        let ks = KeyStore::from_string(content).unwrap();
        assert!(ks.has_key("header_key"));
        assert!(ks.has_key("master_key_00"));
        assert!(ks.has_key("aes_kek_generation_source"));
        assert!(!ks.has_key("nonexistent"));
    }

    #[test]
    fn test_header_key() {
        let content =
            "header_key = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let ks = KeyStore::from_string(content).unwrap();
        let hk = ks.header_key().unwrap();
        assert_eq!(hk.len(), 32);
    }

    #[test]
    fn test_missing_header_key() {
        let content = "master_key_00 = 0123456789abcdef0123456789abcdef";
        let ks = KeyStore::from_string(content).unwrap();
        assert!(ks.header_key().is_err());
    }
}
