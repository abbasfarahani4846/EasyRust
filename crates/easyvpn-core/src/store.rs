use crate::{Profile, ProxyMode, Settings, Subscription};
use anyhow::{Context, Result};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn data_dir() -> PathBuf {
    let path = std::env::var_os("EASYVPN_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            dirs::data_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("EasyVpn")
        });
    let _ = fs::create_dir_all(&path);
    path
}

pub fn new_id() -> String {
    format!("{:08x}", rand::thread_rng().gen::<u32>())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Store {
    pub profiles: Vec<Profile>,
    pub subscriptions: Vec<Subscription>,
    pub settings: Settings,
    pub selected: Option<String>,
}

/// Inspect presence, not the deserialized default: an explicit `mode` always
/// takes precedence over legacy flags, including an explicit "local".
fn decode_store(bytes: &[u8]) -> Result<Store> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    let has_mode = value
        .get("settings")
        .and_then(|settings| settings.as_object())
        .is_some_and(|settings| settings.contains_key("mode"));
    let mut store: Store = serde_json::from_value(value)?;
    if !has_mode {
        store.settings.mode = if store.settings.tun {
            ProxyMode::Tun
        } else if store.settings.system_proxy {
            ProxyMode::System
        } else {
            ProxyMode::Local
        };
    }
    // Do not leave a second, contradictory source of truth in memory.
    store.settings.system_proxy = false;
    store.settings.tun = false;
    Ok(store)
}

impl Store {
    pub fn load() -> Result<Store> {
        let path = data_dir().join("store.json");
        match fs::read(&path) {
            Ok(bytes) => decode_store(&bytes)
                .with_context(|| format!("parsing {}", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn save(&self) -> Result<()> {
        let dir = data_dir();
        fs::create_dir_all(&dir)
            .with_context(|| format!("creating {}", dir.display()))?;
        let bytes = serde_json::to_vec_pretty(self).context("serializing store")?;

        let (temp, mut file) = loop {
            let path = dir.join(format!(".store-{}.tmp", new_id()));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => break (path, file),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error).context("creating temporary store file"),
            }
        };

        let result = (|| -> Result<()> {
            file.write_all(&bytes).context("writing store")?;
            file.write_all(b"\n").context("writing store")?;
            file.sync_all().context("syncing store")?;
            drop(file);
            replace_file(&temp, &dir.join("store.json")).context("replacing store.json")?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }

    pub fn add_profile(&mut self, mut p: Profile) -> String {
        if p.id.is_empty() {
            p.id = self.unused_id();
        }
        let id = p.id.clone();
        self.profiles.push(p);
        id
    }

    pub fn remove_profile(&mut self, id: &str) -> bool {
        let before = self.profiles.len();
        self.profiles.retain(|p| p.id != id);
        let removed = before != self.profiles.len();
        if removed && self.selected.as_deref() == Some(id) {
            self.selected = None;
        }
        removed
    }

    pub fn find(&self, key: &str) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.id == key).or_else(|| {
            key.parse::<usize>()
                .ok()
                .and_then(|index| index.checked_sub(1))
                .and_then(|index| self.profiles.get(index))
        })
    }

    pub fn selected_profile(&self) -> Option<&Profile> {
        let id = self.selected.as_deref()?;
        self.profiles.iter().find(|p| p.id == id)
    }

    pub fn add_subscription(&mut self, name: &str, url: &str) -> String {
        let id = self.unused_id();
        self.subscriptions.push(Subscription {
            id: id.clone(),
            name: name.to_owned(),
            url: url.to_owned(),
            updated_at: 0,
        });
        id
    }

    pub fn remove_subscription(&mut self, id: &str) -> bool {
        let before = self.subscriptions.len();
        self.subscriptions.retain(|sub| sub.id != id);
        let removed = self.subscriptions.len() != before;
        self.profiles
            .retain(|p| p.subscription_id.as_deref() != Some(id));
        if self.selected.is_some() && self.selected_profile().is_none() {
            self.selected = None;
        }
        removed
    }

    fn unused_id(&self) -> String {
        loop {
            let id = new_id();
            if !self.profiles.iter().any(|p| p.id == id)
                && !self.subscriptions.iter().any(|s| s.id == id)
            {
                return id;
            }
        }
    }
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(source: *const u16, destination: *const u16, flags: u32) -> i32;
    }

    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination.as_os_str().encode_wide().chain(Some(0)).collect();
    let success = unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), 0x1 | 0x8) };
    if success == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct TestHome {
        old: Option<OsString>,
        path: PathBuf,
    }

    impl TestHome {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "easyvpn-store-test-{}-{}",
                std::process::id(),
                new_id()
            ));
            let old = std::env::var_os("EASYVPN_HOME");
            std::env::set_var("EASYVPN_HOME", &path);
            Self { old, path }
        }
    }

    impl Drop for TestHome {
        fn drop(&mut self) {
            match &self.old {
                Some(value) => std::env::set_var("EASYVPN_HOME", value),
                None => std::env::remove_var("EASYVPN_HOME"),
            }
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn legacy_mode_migration() -> Result<()> {
        for (json, expected) in [
            (r#"{}"#, ProxyMode::Local),
            (r#"{"settings":{}}"#, ProxyMode::Local),
            (r#"{"settings":{"system_proxy":true}}"#, ProxyMode::System),
            (r#"{"settings":{"tun":true}}"#, ProxyMode::Tun),
            (
                r#"{"settings":{"tun":true,"system_proxy":true}}"#,
                ProxyMode::Tun,
            ),
            (
                r#"{"settings":{"mode":"local","tun":true,"system_proxy":true}}"#,
                ProxyMode::Local,
            ),
            (
                r#"{"settings":{"mode":"system","tun":true}}"#,
                ProxyMode::System,
            ),
        ] {
            let store = decode_store(json.as_bytes())?;
            assert_eq!(store.settings.mode, expected);
            assert!(!store.settings.tun);
            assert!(!store.settings.system_proxy);
            let saved = serde_json::to_value(&store)?;
            assert!(saved["settings"].get("tun").is_none());
            assert!(saved["settings"].get("system_proxy").is_none());
            assert_eq!(decode_store(&serde_json::to_vec(&store)?)?.settings.mode, expected);
        }
        assert!(decode_store(br#"{"settings":{"mode":null}}"#).is_err());
        assert!(decode_store(br#"{"settings":{"mode":"invalid"}}"#).is_err());
        Ok(())
    }

    #[test]
    fn load_migrates_file() -> Result<()> {
        let _lock = ENV_LOCK.lock().expect("test environment lock poisoned");
        let home = TestHome::new();
        fs::create_dir_all(&home.path)?;
        fs::write(
            home.path.join("store.json"),
            br#"{"settings":{"tun":true,"system_proxy":true}}"#,
        )?;
        let store = Store::load()?;
        assert_eq!(store.settings.mode, ProxyMode::Tun);
        store.save()?;
        let saved: serde_json::Value =
            serde_json::from_slice(&fs::read(home.path.join("store.json"))?)?;
        assert_eq!(saved["settings"]["mode"], "tun");
        assert!(saved["settings"].get("tun").is_none());
        Ok(())
    }

    #[test]
    fn persistence_and_operations() -> Result<()> {
        let _lock = ENV_LOCK.lock().expect("test environment lock poisoned");
        let home = TestHome::new();
        assert_eq!(data_dir(), home.path);
        let mut store = Store::load()?;
        assert!(store.profiles.is_empty());

        let id = store.add_profile(Profile {
            name: "Example".into(),
            address: "example.com".into(),
            ..Profile::default()
        });
        assert_eq!(id.len(), 8);
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        assert_eq!(store.find("1").map(|p| &p.id), Some(&id));
        assert!(store.find("0").is_none());
        assert!(store.find("999").is_none());
        store.selected = Some(id.clone());
        assert_eq!(store.selected_profile().map(|p| &p.id), Some(&id));
        store.save()?;
        store.settings.mixed_port = 23456;
        store.save()?;

        let mut loaded = Store::load()?;
        assert_eq!(loaded.profiles, store.profiles);
        assert_eq!(loaded.settings, store.settings);
        assert_eq!(loaded.selected, store.selected);
        assert!(loaded.remove_profile(&id));
        assert!(!loaded.remove_profile(&id));
        assert!(loaded.selected.is_none());

        let sub = loaded.add_subscription("Test", "https://example.com/sub");
        let imported = loaded.add_profile(Profile {
            subscription_id: Some(sub.clone()),
            ..Profile::default()
        });
        loaded.selected = Some(imported);
        loaded.add_profile(Profile::default());
        assert!(loaded.remove_subscription(&sub));
        assert!(!loaded.remove_subscription(&sub));
        assert_eq!(loaded.profiles.len(), 1);
        assert!(loaded.selected.is_none());

        fs::write(home.path.join("store.json"), b"not json")?;
        assert!(Store::load().is_err());
        fs::write(home.path.join("store.json"), b"{}")?;
        assert_eq!(Store::load()?.settings, Settings::default());
        Ok(())
    }
}
