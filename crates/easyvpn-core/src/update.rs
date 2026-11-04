//! Self-update from the public releases repository.
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

/// Releases must be readable without a token, so this repository has to be public.
const REPO: &str = "abbasfarahani4846/EasyRust";
const USER_AGENT: &str = concat!("EasyVpn/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    pub version: String,
    pub url: String,
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

/// Release asset that matches this build, if updating is supported here.
pub fn asset_name() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("android", "aarch64") => Some("EasyVpn-arm64.apk"),
        ("android", "x86_64") => Some("EasyVpn-x86_64.apk"),
        ("windows", _) => Some("easyvpn-gui.exe"),
        _ => None,
    }
}

fn parts(version: &str) -> Vec<u64> {
    version
        .trim_start_matches('v')
        .split('.')
        .map(|part| part.parse().unwrap_or(0))
        .collect()
}

pub fn is_newer(latest: &str, current: &str) -> bool {
    let (mut a, mut b) = (parts(latest), parts(current));
    let len = a.len().max(b.len());
    a.resize(len, 0);
    b.resize(len, 0);
    a > b
}

fn agent(proxy: Option<&str>, timeout: Duration) -> Result<ureq::Agent> {
    let mut builder = ureq::AgentBuilder::new().try_proxy_from_env(false).timeout(timeout);
    if let Some(url) = proxy {
        builder = builder.proxy(ureq::Proxy::new(url).context("invalid proxy URL")?);
    }
    Ok(builder.build())
}

fn pick(release: Release, current: &str, asset: &str) -> Result<Option<Update>> {
    if !is_newer(&release.tag_name, current) {
        return Ok(None);
    }
    let url = release
        .assets
        .into_iter()
        .find(|candidate| candidate.name == asset)
        .map(|candidate| candidate.browser_download_url)
        .with_context(|| format!("release {} has no {asset}", release.tag_name))?;
    Ok(Some(Update { version: release.tag_name.trim_start_matches('v').to_owned(), url }))
}

/// `Ok(None)` means this build is already the newest. `proxy` routes the check through a live tunnel.
pub fn check(proxy: Option<&str>) -> Result<Option<Update>> {
    let asset = asset_name().context("updates are not available on this platform")?;
    let release: Release = agent(proxy, Duration::from_secs(20))?
        .get(&format!("https://api.github.com/repos/{REPO}/releases/latest"))
        .set("User-Agent", USER_AGENT)
        .set("Accept", "application/vnd.github+json")
        .call()
        .context("checking for updates")?
        .into_json()
        .context("decoding release")?;
    pick(release, env!("CARGO_PKG_VERSION"), asset)
}

/// Where a download is staged: next to the executable on Windows (rename needs one volume).
pub fn staging_path(data_dir: &Path) -> PathBuf {
    if cfg!(windows) {
        if let Ok(exe) = std::env::current_exe() {
            return exe.with_extension("exe.new");
        }
    }
    data_dir.join("update.apk")
}

pub fn download(url: &str, dest: &Path, proxy: Option<&str>, progress: &mut dyn FnMut(String)) -> Result<()> {
    let response = agent(proxy, Duration::from_secs(600))?
        .get(url)
        .set("User-Agent", USER_AGENT)
        .call()
        .context("downloading update")?;
    let total = response.header("Content-Length").and_then(|v| v.parse::<u64>().ok()).filter(|v| *v > 0);
    let mut reader = response.into_reader();
    let mut file = File::create(dest)?;
    let mut buffer = [0u8; 64 * 1024];
    let (mut received, mut last) = (0u64, 101u64);
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        file.write_all(&buffer[..count])?;
        received += count as u64;
        let percent = total.map_or(0, |t| received * 100 / t);
        if percent != last {
            progress(format!("Downloading update… {percent}%"));
            last = percent;
        }
    }
    if let Some(total) = total {
        if total != received {
            bail!("incomplete download: expected {total} bytes, received {received}");
        }
    }
    file.sync_all()?;
    Ok(())
}

/// Windows: swap the running exe for the downloaded one and start it. A running exe can be renamed, not overwritten.
pub fn replace_self_and_restart(new: &Path) -> Result<()> {
    let exe = std::env::current_exe()?;
    let old = exe.with_extension("exe.old");
    let _ = std::fs::remove_file(&old);
    std::fs::rename(&exe, &old).context("cannot replace the running program (is the folder writable?)")?;
    if let Err(error) = std::fs::rename(new, &exe) {
        let _ = std::fs::rename(&old, &exe);
        return Err(error).context("cannot move the new version into place");
    }
    std::process::Command::new(&exe).spawn().context("cannot start the new version")?;
    std::process::exit(0);
}

/// Remove the previous exe left behind by `replace_self_and_restart`.
pub fn cleanup() {
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::fs::remove_file(exe.with_extension("exe.old"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_order() {
        assert!(is_newer("v0.1.1", "0.1.0"));
        assert!(is_newer("0.2", "0.1.9"));
        assert!(is_newer("v1.0.0", "0.9.9"));
        assert!(!is_newer("v0.1.0", "0.1.0"));
        assert!(!is_newer("v0.1.0", "0.1.1"));
    }

    #[test]
    fn picks_matching_asset_only_when_newer() {
        let release = || Release {
            tag_name: "v0.2.0".into(),
            assets: vec![Asset { name: "EasyVpn-arm64.apk".into(), browser_download_url: "https://x/a".into() }],
        };
        assert_eq!(pick(release(), "0.1.0", "EasyVpn-arm64.apk").unwrap().unwrap().version, "0.2.0");
        assert!(pick(release(), "0.2.0", "EasyVpn-arm64.apk").unwrap().is_none());
        assert!(pick(release(), "0.1.0", "missing").is_err());
    }
}
