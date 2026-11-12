//! Engine pack manifests (Ghidra, rizin, ILSpyCmd, jadx, ...), installers and checks.
//!
//! Installers deliberately use tools that ship with the OS (`curl`, `tar`) or the dotnet
//! SDK (`dotnet tool`) instead of pulling an HTTP/TLS stack into the binary.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Healthcheck {
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default)]
    pub timeout_s: u64,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct InstallSpec {
    /// `zip` (default) or `dotnet-tool`
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub package: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DownloadSpec {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub archive: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EngineManifest {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub version: String,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub integration: Option<String>,
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default)]
    pub binaries: Vec<String>,
    #[serde(default)]
    pub install_dir: Option<String>,
    #[serde(default)]
    pub healthcheck: Option<Healthcheck>,
    #[serde(default)]
    pub install: Option<InstallSpec>,
    #[serde(default)]
    pub download: std::collections::BTreeMap<String, DownloadSpec>,
}

#[derive(Debug, Clone, Default)]
pub struct InstallOptions {
    pub from: Option<PathBuf>,
    pub allow_unpinned: bool,
    pub force: bool,
}

/// Best-effort repository root: walk up from the executable and from the cwd until a
/// directory contains both `engines/` and `Cargo.toml`.
pub fn repo_root() -> PathBuf {
    if let Ok(executable) = std::env::current_exe() {
        for ancestor in executable.ancestors().skip(1) {
            if ancestor.join("engines").is_dir() && ancestor.join("Cargo.toml").is_file() {
                return ancestor.to_path_buf();
            }
        }
    }
    let mut directory = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    loop {
        if directory.join("engines").is_dir() {
            return directory;
        }
        if !directory.pop() {
            break;
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

pub fn engines_dir() -> PathBuf {
    repo_root().join("engines")
}

pub fn load_manifests() -> Vec<EngineManifest> {
    let directory = engines_dir();
    let mut manifests = Vec::new();
    let Ok(entries) = std::fs::read_dir(&directory) else {
        return manifests;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("toml") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        match toml::from_str::<EngineManifest>(&text) {
            Ok(manifest) => manifests.push(manifest),
            Err(error) => eprintln!("! skipping {}: {error}", path.display()),
        }
    }
    manifests.sort_by(|left, right| left.id.cmp(&right.id));
    manifests
}

pub fn manifest_path(id: &str) -> PathBuf {
    engines_dir().join(format!("{id}.toml"))
}

/// Resolve an executable on `PATH` (adds `.exe` on Windows).
pub fn which(tool: &str) -> Option<PathBuf> {
    let candidate = Path::new(tool);
    if candidate.components().count() > 1 {
        return candidate.is_file().then(|| candidate.to_path_buf());
    }
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        let direct = directory.join(tool);
        if direct.is_file() {
            return Some(direct);
        }
        #[cfg(windows)]
        {
            let with_exe = directory.join(format!("{tool}.exe"));
            if with_exe.is_file() {
                return Some(with_exe);
            }
        }
    }
    None
}

pub fn install_dir_of(manifest: &EngineManifest) -> PathBuf {
    match &manifest.install_dir {
        Some(relative) => repo_root().join(relative),
        None => engines_dir().join(&manifest.id).join(&manifest.version),
    }
}

pub fn is_installed(manifest: &EngineManifest) -> bool {
    if install_dir_of(manifest).exists() {
        return true;
    }
    if manifest
        .binaries
        .iter()
        .any(|binary| which(binary).is_some())
    {
        return true;
    }
    manifest
        .healthcheck
        .as_ref()
        .and_then(|healthcheck| healthcheck.command.first())
        .and_then(|command| which(command))
        .is_some()
}

/// Recursively search an installed engine directory for an executable basename.
pub fn find_binary(directory: &Path, name: &str) -> Option<PathBuf> {
    fn walk(directory: &Path, candidate: &str, depth: usize) -> Option<PathBuf> {
        if depth > 5 {
            return None;
        }
        let entries = std::fs::read_dir(directory).ok()?;
        let mut subdirectories = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                subdirectories.push(path);
                continue;
            }
            let file_name = path.file_name()?.to_string_lossy().to_lowercase();
            if file_name == candidate {
                return Some(path);
            }
        }
        for subdirectory in subdirectories {
            if let Some(found) = walk(&subdirectory, candidate, depth + 1) {
                return Some(found);
            }
        }
        None
    }
    let lower = name.to_lowercase();
    if lower.ends_with(".exe") || lower.ends_with(".cmd") || lower.ends_with(".bat") {
        return walk(directory, &lower, 0);
    }
    // Prefer a real executable over a shell shim.
    for candidate in [
        format!("{lower}.exe"),
        format!("{lower}.cmd"),
        format!("{lower}.bat"),
        lower,
    ] {
        if let Some(found) = walk(directory, &candidate, 0) {
            return Some(found);
        }
    }
    None
}

/// Build a `Command` that works for real executables as well as `.cmd`/`.bat` shims.
pub fn command_for_binary(path: &Path) -> Command {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if extension == "cmd" || extension == "bat" {
        let mut command = Command::new("cmd");
        command.arg("/c").arg(path);
        command
    } else {
        Command::new(path)
    }
}

pub fn manifest_binary_path(manifest: &EngineManifest) -> Option<PathBuf> {
    let directory = install_dir_of(manifest);
    if directory.exists() {
        for binary in &manifest.binaries {
            if let Some(path) = find_binary(&directory, binary) {
                return Some(path);
            }
        }
    }
    for binary in &manifest.binaries {
        if let Some(path) = which(binary) {
            return Some(path);
        }
    }
    None
}

pub fn platform_key() -> &'static str {
    if cfg!(target_os = "windows") {
        if cfg!(target_arch = "aarch64") {
            "windows-arm64"
        } else {
            "windows-x64"
        }
    } else if cfg!(target_os = "macos") {
        if cfg!(target_arch = "aarch64") {
            "macos-arm64"
        } else {
            "macos-x64"
        }
    } else if cfg!(target_arch = "aarch64") {
        "linux-arm64"
    } else {
        "linux-x64"
    }
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let mut hasher = Sha256::new();
    // Heap buffer: the Windows main-thread stack is small; a 1 MiB stack array overflows.
    let mut buffer = vec![0u8; 256 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn is_pinned(hash: &str) -> bool {
    hash.len() == 64 && hash.chars().all(|character| character.is_ascii_hexdigit())
}

fn cache_archive_path(manifest: &EngineManifest, platform: &str, spec: &DownloadSpec) -> PathBuf {
    let extension = spec
        .archive
        .clone()
        .or_else(|| spec.url.rsplit('/').next().map(|name| name.to_string()))
        .unwrap_or_else(|| "zip".to_string());
    engines_dir().join(".cache").join(format!(
        "{}-{}-{platform}.{extension}",
        manifest.id, manifest.version
    ))
}

fn run_checked(command: &mut Command, what: &str) -> Result<()> {
    let output = command
        .output()
        .with_context(|| format!("cannot run {what}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(anyhow!(
            "{what} failed ({}): {}{}",
            output.status,
            stderr.chars().take(800).collect::<String>(),
            stdout.chars().take(400).collect::<String>()
        ));
    }
    Ok(())
}

/// Download (or reuse a cached/offline archive) for the current platform.
fn fetch_archive(
    manifest: &EngineManifest,
    platform: &str,
    options: &InstallOptions,
) -> Result<PathBuf> {
    if let Some(path) = &options.from {
        if !path.is_file() {
            return Err(anyhow!("archive not found: {}", path.display()));
        }
        return Ok(path.clone());
    }
    let spec = manifest.download.get(platform).ok_or_else(|| {
        anyhow!(
            "manifest {} has no download spec for {platform}",
            manifest.id
        )
    })?;
    if spec.url.is_empty() {
        return Err(anyhow!(
            "manifest {} has no download URL for {platform}",
            manifest.id
        ));
    }
    let archive = cache_archive_path(manifest, platform, spec);
    if archive.is_file() {
        return Ok(archive);
    }
    if let Some(parent) = archive.parent() {
        std::fs::create_dir_all(parent)?;
    }
    eprintln!(
        "downloading {} {} ({platform}) ...",
        manifest.id, manifest.version
    );
    run_checked(
        Command::new("curl").args([
            "-L",
            "--fail",
            "--retry",
            "3",
            "--silent",
            "--show-error",
            "-o",
            &archive.to_string_lossy(),
            &spec.url,
        ]),
        "curl download",
    )?;
    Ok(archive)
}

fn copy_directory(source: &Path, destination: &Path) -> Result<()> {
    std::fs::create_dir_all(destination)?;
    for entry in std::fs::read_dir(source)?.flatten() {
        let path = entry.path();
        let target = destination.join(entry.file_name());
        if path.is_dir() {
            copy_directory(&path, &target)?;
        } else {
            std::fs::copy(&path, &target)?;
        }
    }
    Ok(())
}

fn extract_and_place(archive: &Path, install_dir: &Path) -> Result<()> {
    let temp = engines_dir().join(".tmp").join(format!(
        "{}-{}",
        std::process::id(),
        crate::util::now_iso8601().replace(':', "")
    ));
    std::fs::create_dir_all(&temp)?;
    run_checked(
        Command::new("tar").args([
            "-xf",
            &archive.to_string_lossy(),
            "-C",
            &temp.to_string_lossy(),
        ]),
        "tar extract",
    )?;
    // Prefer a single extracted top-level directory (typical release archive layout).
    let entries: Vec<PathBuf> = std::fs::read_dir(&temp)?
        .flatten()
        .map(|entry| entry.path())
        .collect();
    let source = if entries.len() == 1 && entries[0].is_dir() {
        entries[0].clone()
    } else {
        temp.clone()
    };
    if install_dir.exists() {
        std::fs::remove_dir_all(install_dir)?;
    }
    if let Some(parent) = install_dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::rename(&source, install_dir) {
        Ok(()) => {}
        Err(_) => {
            copy_directory(&source, install_dir)?;
        }
    }
    if temp.exists() {
        let _ = std::fs::remove_dir_all(&temp);
    }
    Ok(())
}

fn install_zip(
    manifest: &EngineManifest,
    install_dir: &Path,
    options: &InstallOptions,
) -> Result<PathBuf> {
    let platform = platform_key();
    let spec = manifest.download.get(platform).ok_or_else(|| {
        anyhow!(
            "manifest {} has no download spec for {platform}",
            manifest.id
        )
    })?;
    let archive = fetch_archive(manifest, platform, options)?;
    if let Some(expected) = &spec.sha256 {
        if is_pinned(expected) {
            let actual = sha256_file(&archive)?;
            if !actual.eq_ignore_ascii_case(expected) {
                return Err(anyhow!(
                    "SHA-256 mismatch for {}: expected {}, got {}",
                    manifest.id,
                    expected,
                    actual
                ));
            }
        } else if !options.allow_unpinned {
            return Err(anyhow!(
                "manifest {} has no pinned SHA-256 for {platform}. Run `avero engine pin {}` first, \
                 or pass --allow-unpinned for a trusted local archive.",
                manifest.id,
                manifest.id
            ));
        }
    }
    extract_and_place(&archive, install_dir)?;
    Ok(install_dir.to_path_buf())
}

fn install_dotnet_tool(manifest: &EngineManifest, install_dir: &Path) -> Result<PathBuf> {
    let spec = manifest
        .install
        .as_ref()
        .ok_or_else(|| anyhow!("manifest {} has no [install] section", manifest.id))?;
    let package = spec
        .package
        .clone()
        .ok_or_else(|| anyhow!("dotnet-tool manifest {} has no package", manifest.id))?;
    let version = spec
        .version
        .clone()
        .unwrap_or_else(|| manifest.version.clone());
    std::fs::create_dir_all(install_dir)?;
    run_checked(
        Command::new("dotnet").args([
            "tool",
            "install",
            "--tool-path",
            &install_dir.to_string_lossy(),
            &package,
            "--version",
            &version,
        ]),
        "dotnet tool install",
    )?;
    Ok(install_dir.to_path_buf())
}

/// Install an engine pack. Returns the install directory.
pub fn install_engine(manifest: &EngineManifest, options: &InstallOptions) -> Result<PathBuf> {
    let install_dir = install_dir_of(manifest);
    if install_dir.exists() && !options.force {
        return Ok(install_dir);
    }
    let method = manifest
        .install
        .as_ref()
        .and_then(|install| install.method.as_deref())
        .unwrap_or("zip");
    let path = match method {
        "dotnet-tool" => install_dotnet_tool(manifest, &install_dir)?,
        "zip" => install_zip(manifest, &install_dir, options)?,
        other => return Err(anyhow!("unsupported install method `{other}`")),
    };
    if !manifest.binaries.is_empty() && manifest_binary_path(manifest).is_none() {
        return Err(anyhow!(
            "installed {} but none of the expected binaries were found: {}",
            manifest.id,
            manifest.binaries.join(", ")
        ));
    }
    Ok(path)
}

/// Download the archive and write its SHA-256 into the manifest for pinning.
pub fn pin_engine(id: &str, options: &InstallOptions) -> Result<(String, PathBuf)> {
    let manifest = load_manifests()
        .into_iter()
        .find(|manifest| manifest.id == id)
        .ok_or_else(|| anyhow!("unknown engine `{id}`"))?;
    let platform = platform_key();
    let archive = fetch_archive(&manifest, platform, options)?;
    let hash = sha256_file(&archive)?;
    let path = manifest_path(id);
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read {}", path.display()))?;
    let mut document: toml_edit::DocumentMut = text.parse()?;
    let download = document["download"]
        .as_table_mut()
        .ok_or_else(|| anyhow!("manifest has no [download] table"))?;
    let platform_table = download
        .entry(platform)
        .or_insert(toml_edit::Item::Table(toml_edit::Table::new()))
        .as_table_mut()
        .ok_or_else(|| anyhow!("bad [download.{platform}] table"))?;
    platform_table["sha256"] = toml_edit::value(hash.clone());
    std::fs::write(&path, document.to_string())?;
    Ok((hash, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_parses_download_and_install() {
        let manifest: EngineManifest = toml::from_str(
            r#"
id = "rizin"
name = "Rizin"
version = "0.9.1"
license = "LGPL-3.0"
integration = "sidecar"
install_dir = "engines/rizin/0.9.1"
binaries = ["rizin"]

[install]
method = "zip"

[download.windows-x64]
url = "https://example.com/rizin.zip"
sha256 = "PIN"

[healthcheck]
command = ["rizin", "-v"]
timeout_s = 30
"#,
        )
        .expect("manifest parses");
        assert_eq!(manifest.install.unwrap().method.as_deref(), Some("zip"));
        assert!(manifest.download.contains_key("windows-x64"));
        assert_eq!(platform_key().is_empty(), false);
    }

    #[test]
    fn sha256_file_matches_known_value() {
        let directory = std::env::temp_dir().join(format!("avero-sha-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("abc.txt");
        std::fs::write(&path, b"abc").unwrap();
        let hash = sha256_file(&path).expect("hash");
        assert_eq!(
            hash,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn find_binary_searches_subdirectories() {
        let directory = std::env::temp_dir().join(format!("avero-bin-{}", std::process::id()));
        let nested = directory.join("bin");
        std::fs::create_dir_all(&nested).unwrap();
        let binary = nested.join("rizin.exe");
        std::fs::write(&binary, b"stub").unwrap();
        assert_eq!(find_binary(&directory, "rizin"), Some(binary));
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn which_finds_a_known_tool() {
        #[cfg(windows)]
        assert!(which("cmd").is_some());
        #[cfg(not(windows))]
        assert!(which("sh").is_some());
    }
}
