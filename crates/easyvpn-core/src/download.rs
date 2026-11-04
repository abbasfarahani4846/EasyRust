#[cfg(not(target_os = "android"))]
use crate::core::{binary_path, cores_dir, executable_name};
use crate::profile::CoreKind;
use anyhow::{bail, Result};
#[cfg(not(target_os = "android"))]
use anyhow::Context;
#[cfg(not(target_os = "android"))]
use flate2::read::GzDecoder;
#[cfg(not(target_os = "android"))]
use serde::Deserialize;
#[cfg(not(target_os = "android"))]
use std::fs::{self, File};
#[cfg(not(target_os = "android"))]
use std::io::{self, Read, Write};
#[cfg(not(target_os = "android"))]
use std::path::Path;
use std::path::PathBuf;
#[cfg(not(target_os = "android"))]
use std::time::Duration;

#[cfg(not(target_os = "android"))]
const USER_AGENT: &str = "EasyVpn";

#[cfg(not(target_os = "android"))]
#[derive(Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<Asset>,
}

#[cfg(not(target_os = "android"))]
#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

#[cfg(not(target_os = "android"))]
fn openvpn_install_hint() -> &'static str {
    match std::env::consts::OS {
        "windows" => {
            "OpenVPN is not downloadable by EasyVpn; install it with: winget install OpenVPNTechnologies.OpenVPN"
        }
        "macos" => {
            "OpenVPN is not downloadable by EasyVpn; install it with: brew install openvpn"
        }
        _ => {
            "OpenVPN is not downloadable by EasyVpn; Debian/Ubuntu: sudo apt install openvpn; Fedora: sudo dnf install openvpn"
        }
    }
}

#[cfg(not(target_os = "android"))]
fn release(kind: CoreKind) -> Result<Release> {
    let repo = match kind {
        CoreKind::Xray => "XTLS/Xray-core",
        CoreKind::SingBox => "SagerNet/sing-box",
        CoreKind::Mihomo => "MetaCubeX/mihomo",
        CoreKind::OpenVpn => bail!("{}", openvpn_install_hint()),
    };
    let response = ureq::get(&format!(
        "https://api.github.com/repos/{repo}/releases/latest"
    ))
    .set("User-Agent", USER_AGENT)
    .set("Accept", "application/vnd.github+json")
    .timeout(Duration::from_secs(30))
    .call()
    .with_context(|| format!("fetching latest {} release", kind.name()))?;
    let release: Release = response.into_json().context("decoding GitHub release")?;
    if release.tag_name.is_empty() {
        bail!("GitHub returned an empty release tag");
    }
    Ok(release)
}

pub fn latest_version(kind: CoreKind) -> Result<String> {
    #[cfg(target_os = "android")]
    {
        let _ = kind;
        bail!("cores are bundled with the Android app");
    }
    #[cfg(not(target_os = "android"))]
    {
        Ok(release(kind)?.tag_name)
    }
}

pub fn pick_asset(
    kind: CoreKind,
    os: &str,
    arch: &str,
    names: &[String],
) -> Option<String> {
    if kind == CoreKind::OpenVpn {
        return None;
    }
    let arch = match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => return None,
    };
    if !matches!(os, "windows" | "linux" | "macos") {
        return None;
    }

    if kind == CoreKind::Xray {
        let platform = if os == "macos" { "macos" } else { os };
        let cpu = if arch == "amd64" { "64" } else { "arm64-v8a" };
        let target = format!("Xray-{platform}-{cpu}.zip");
        return names
            .iter()
            .find(|name| name.eq_ignore_ascii_case(&target))
            .cloned();
    }

    let platform = if os == "macos" { "darwin" } else { os };
    let suffix = if os == "windows" {
        ".zip"
    } else if kind == CoreKind::SingBox {
        ".tar.gz"
    } else {
        ".gz"
    };

    let mut candidates: Vec<&String> = names
        .iter()
        .filter(|name| {
            let name = name.to_ascii_lowercase();
            if !name.ends_with(suffix) {
                return false;
            }
            match kind {
                CoreKind::SingBox => {
                    name.starts_with("sing-box-")
                        && name.ends_with(&format!("-{platform}-{arch}{suffix}"))
                        && ![
                            "-legacy", "-glibc", "-musl", "-purego", "android", "ios",
                        ]
                        .iter()
                        .any(|bad| name.contains(bad))
                }
                CoreKind::Mihomo => {
                    let prefix = format!("mihomo-{platform}-{arch}-");
                    if !name.starts_with(&prefix)
                        || ["go1", "-v1-", "-v2-", "-v3-", "alpha"]
                            .iter()
                            .any(|bad| name.contains(bad))
                    {
                        return false;
                    }
                    // Only a plain version or the amd64 compatibility variant.
                    let tail = &name[prefix.len()..];
                    tail.starts_with('v')
                        || (arch == "amd64" && tail.starts_with("compatible-v"))
                }
                CoreKind::Xray | CoreKind::OpenVpn => false,
            }
        })
        .collect();

    // Deterministic selection, with the portable amd64 build preferred.
    candidates.sort_by(|a, b| {
        let rank = |name: &str| {
            if kind == CoreKind::Mihomo
                && arch == "amd64"
                && name.contains("-compatible-")
            {
                0
            } else {
                1
            }
        };
        rank(a).cmp(&rank(b)).then_with(|| a.cmp(b))
    });
    candidates.first().map(|name| (*name).clone())
}

#[cfg(not(target_os = "android"))]
struct TempDir(PathBuf);

#[cfg(not(target_os = "android"))]
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(not(target_os = "android"))]
fn temporary_directory(parent: &Path) -> Result<TempDir> {
    for _ in 0..10 {
        let path = parent.join(format!(".install-{:016x}", rand::random::<u64>()));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(TempDir(path)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    bail!("could not allocate a temporary installation directory")
}

#[cfg(not(target_os = "android"))]
fn download(url: &str, path: &Path, progress: &mut dyn FnMut(String)) -> Result<()> {
    let response = ureq::get(url)
        .set("User-Agent", USER_AGENT)
        .timeout(Duration::from_secs(300))
        .call()
        .context("downloading core archive")?;
    let total = response
        .header("Content-Length")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0);
    let mut reader = response.into_reader();
    let mut file = File::create(path)?;
    let mut buffer = [0u8; 64 * 1024];
    let mut received = 0u64;
    let mut last_report = None;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        file.write_all(&buffer[..count])?;
        received += count as u64;
        let report = match total {
            Some(total) => format!("downloading ... {}%", received.saturating_mul(100) / total),
            None => format!("downloading ... {} KiB", received / 1024),
        };
        if last_report.as_ref() != Some(&report) {
            progress(report.clone());
            last_report = Some(report);
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

// Archive paths are never used as output paths: only explicitly allowed basenames
// are copied into our private staging directory.
#[cfg(not(target_os = "android"))]
fn output_name(kind: CoreKind, entry: &Path) -> Option<String> {
    let name = entry.file_name()?.to_str()?;
    let exe = executable_name(kind);
    if name == exe
        || (kind == CoreKind::Mihomo
            && cfg!(windows)
            && name.to_ascii_lowercase().ends_with(".exe"))
    {
        Some(exe)
    } else if kind == CoreKind::Xray && matches!(name, "geoip.dat" | "geosite.dat") {
        Some(name.to_owned())
    } else {
        None
    }
}

#[cfg(not(target_os = "android"))]
fn copy_entry(mut reader: impl Read, target: &Path) -> Result<()> {
    // Refuse duplicate entries rather than allowing ambiguous archive contents.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)?;
    io::copy(&mut reader, &mut file)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(target_os = "android"))]
fn extract(kind: CoreKind, asset: &str, archive: &Path, output: &Path) -> Result<()> {
    let file = File::open(archive)?;
    if asset.ends_with(".zip") {
        let mut zip = zip::ZipArchive::new(file).context("opening zip archive")?;
        for index in 0..zip.len() {
            let mut entry = zip.by_index(index)?;
            if entry.is_dir() {
                continue;
            }
            if let Some(name) = output_name(kind, Path::new(entry.name())) {
                copy_entry(&mut entry, &output.join(name))?;
            }
        }
    } else if asset.ends_with(".tar.gz") {
        let mut tar = tar::Archive::new(GzDecoder::new(file));
        for entry in tar.entries()? {
            let mut entry = entry?;
            if !entry.header().entry_type().is_file() {
                continue;
            }
            let name = output_name(kind, entry.path()?.as_ref());
            if let Some(name) = name {
                copy_entry(&mut entry, &output.join(name))?;
            }
        }
    } else if kind == CoreKind::Mihomo && asset.ends_with(".gz") {
        copy_entry(
            GzDecoder::new(file),
            &output.join(executable_name(kind)),
        )?;
    } else {
        bail!("unsupported archive format: {asset}");
    }

    let executable = output.join(executable_name(kind));
    if !executable.is_file() || executable.metadata()?.len() == 0 {
        bail!("archive does not contain a nonempty {} binary", kind.name());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

pub fn install(
    kind: CoreKind,
    progress: &mut dyn FnMut(String),
) -> Result<PathBuf> {
    #[cfg(target_os = "android")]
    {
        let _ = (kind, progress);
        bail!("cores are bundled with the Android app");
    }

    #[cfg(not(target_os = "android"))]
    {
        if kind == CoreKind::OpenVpn {
            bail!("{}", openvpn_install_hint());
        }
        progress(format!("checking latest {} release", kind.name()));
        let release = release(kind)?;
        let names: Vec<String> = release.assets.iter().map(|asset| asset.name.clone()).collect();
        let name = pick_asset(
            kind,
            std::env::consts::OS,
            std::env::consts::ARCH,
            &names,
        )
        .with_context(|| {
            format!(
                "no {} asset for {} / {}",
                kind.name(),
                std::env::consts::OS,
                std::env::consts::ARCH
            )
        })?;
        let asset = release
            .assets
            .iter()
            .find(|asset| asset.name == name)
            .context("selected asset missing from release")?;

        let parent = cores_dir();
        fs::create_dir_all(&parent).context("creating cores directory")?;
        let staging = temporary_directory(&parent)?;
        let archive = staging.0.join("download");
        progress(format!("downloading {name}"));
        download(&asset.browser_download_url, &archive, progress)?;
        let output = staging.0.join("extracted");
        fs::create_dir(&output)?;
        progress(format!("extracting {name}"));
        extract(kind, &name, &archive, &output).context("extracting core archive")?;
        fs::write(output.join("version.txt"), format!("{}\n", release.tag_name))?;

        let destination = parent.join(kind.name());
        fs::create_dir_all(&destination)?;
        // Copy support files first and publish the version only after the executable.
        for support in ["geoip.dat", "geosite.dat"] {
            let source = output.join(support);
            if source.is_file() {
                fs::copy(&source, destination.join(support))?;
            }
        }
        let exe = executable_name(kind);
        let target = destination.join(&exe);
        #[cfg(windows)]
        if target.exists() {
            fs::remove_file(&target).context("removing previous core; stop it before updating")?;
        }
        fs::rename(output.join(&exe), &target).context("installing core binary")?;
        fs::copy(output.join("version.txt"), destination.join("version.txt"))?;
        progress(format!("installed {} {}", kind.name(), release.tag_name));
        Ok(binary_path(kind))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xray_platforms() {
        for os in ["windows", "linux", "macos"] {
            for (arch, suffix) in [("x86_64", "64"), ("aarch64", "arm64-v8a")] {
                let expected = format!("Xray-{os}-{suffix}.zip");
                let names = vec![
                    format!("{expected}.dgst"),
                    "Xray-linux-32.zip".into(),
                    expected.clone(),
                ];
                assert_eq!(
                    pick_asset(CoreKind::Xray, os, arch, &names),
                    Some(expected)
                );
            }
        }
    }

    #[test]
    fn singbox_platforms_and_variants() {
        for os in ["windows", "linux", "macos"] {
            for (arch, cpu) in [("x86_64", "amd64"), ("aarch64", "arm64")] {
                let platform = if os == "macos" { "darwin" } else { os };
                let extension = if os == "windows" { "zip" } else { "tar.gz" };
                let stem = format!("sing-box-1.12.4-{platform}-{cpu}");
                let expected = format!("{stem}.{extension}");
                let mut names = vec![
                    format!("{stem}-legacy.{extension}"),
                    format!("{stem}-glibc.{extension}"),
                    format!("{stem}-musl.{extension}"),
                    format!("{stem}-purego.{extension}"),
                    format!("{stem}.deb"),
                    format!("{stem}.rpm"),
                    format!("{stem}.pkg.tar.zst"),
                    format!("{stem}.apk"),
                    format!("sing-box-1.12.4-android-{cpu}.tar.gz"),
                    format!("sing-box-1.12.4-ios-{cpu}.tar.gz"),
                ];
                assert_eq!(pick_asset(CoreKind::SingBox, os, arch, &names), None);
                names.push(expected.clone());
                assert_eq!(
                    pick_asset(CoreKind::SingBox, os, arch, &names),
                    Some(expected)
                );
            }
        }
    }

    #[test]
    fn mihomo_platforms_and_compatibility_preference() {
        for os in ["windows", "linux", "macos"] {
            for (arch, cpu) in [("x86_64", "amd64"), ("aarch64", "arm64")] {
                let platform = if os == "macos" { "darwin" } else { os };
                let extension = if os == "windows" { "zip" } else { "gz" };
                let stem = format!("mihomo-{platform}-{cpu}");
                let plain = format!("{stem}-v1.19.15.{extension}");
                let expected = if cpu == "amd64" {
                    format!("{stem}-compatible-v1.19.15.{extension}")
                } else {
                    plain.clone()
                };
                let mut names = vec![
                    format!("{stem}-v1-v1.19.15.{extension}"),
                    format!("{stem}-v2-v1.19.15.{extension}"),
                    format!("{stem}-v3-v1.19.15.{extension}"),
                    format!("{stem}-go120-v1.19.15.{extension}"),
                    format!("{stem}-alpha-v1.19.15.{extension}"),
                    format!("{stem}-v1.19.15.deb"),
                    format!("{stem}-v1.19.15.rpm"),
                    format!("{stem}-v1.19.15.pkg.tar.zst"),
                ];
                assert_eq!(pick_asset(CoreKind::Mihomo, os, arch, &names), None);
                names.push(plain.clone());
                assert_eq!(
                    pick_asset(CoreKind::Mihomo, os, arch, &names),
                    Some(plain)
                );
                names.push(expected.clone());
                assert_eq!(
                    pick_asset(CoreKind::Mihomo, os, arch, &names),
                    Some(expected)
                );
            }
        }
    }

    #[test]
    fn unsupported_platforms_and_empty_lists() {
        for kind in CoreKind::ALL {
            assert_eq!(pick_asset(kind, "freebsd", "x86_64", &[]), None);
            assert_eq!(pick_asset(kind, "linux", "riscv64", &[]), None);
            assert_eq!(pick_asset(kind, "linux", "x86_64", &[]), None);
        }
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn openvpn_is_not_downloadable() {
        for os in ["windows", "linux", "macos"] {
            for arch in ["x86_64", "aarch64"] {
                let names = vec![
                    "openvpn.zip".into(),
                    "openvpn.tar.gz".into(),
                    "openvpn.exe".into(),
                ];
                assert_eq!(pick_asset(CoreKind::OpenVpn, os, arch, &names), None);
            }
        }
        let error = latest_version(CoreKind::OpenVpn).expect_err("not downloadable");
        assert!(error.to_string().contains(openvpn_install_hint()));
        let mut progress = Vec::new();
        let error = install(CoreKind::OpenVpn, &mut |line| progress.push(line))
            .expect_err("not downloadable");
        assert!(error.to_string().contains(openvpn_install_hint()));
        assert!(progress.is_empty());
    }

    #[cfg(target_os = "android")]
    #[test]
    fn android_cores_are_bundled() {
        for kind in CoreKind::ALL {
            let error = latest_version(kind).expect_err("bundled core");
            assert_eq!(error.to_string(), "cores are bundled with the Android app");
            let mut progress = Vec::new();
            let error = install(kind, &mut |line| progress.push(line))
                .expect_err("bundled core");
            assert_eq!(error.to_string(), "cores are bundled with the Android app");
            assert!(progress.is_empty());
        }
    }
}
