//! Finds the CLI, and downloads a release when none is installed.

use crate::Error;
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

/// The CLI release this crate downloads when none is installed.
pub const ENGINE_VERSION: &str = "0.2.0";
const RELEASES: &str = "https://github.com/sendscore/sendscore/releases/download";
const MAX_DOWNLOAD: u64 = 100 << 20;

fn fail(message: String) -> Error {
    Error {
        message,
        exit_code: 0,
    }
}

fn platform() -> Result<(&'static str, &'static str), Error> {
    let os = match env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        "windows" => "windows",
        other => return Err(fail(format!("no SendScore build for {other}"))),
    };
    let arch = match env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => return Err(fail(format!("no SendScore build for {other}"))),
    };
    Ok((os, arch))
}

fn cache_root() -> Option<PathBuf> {
    let home = || env::var_os("HOME").or_else(|| env::var_os("USERPROFILE")).map(PathBuf::from);
    match env::consts::OS {
        "macos" => Some(home()?.join("Library/Caches")),
        "windows" => env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .or_else(|| Some(home()?.join("AppData/Local"))),
        _ => env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| Some(home()?.join(".cache"))),
    }
}

fn executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

fn exe_name() -> &'static str {
    if cfg!(windows) {
        "sendscore.exe"
    } else {
        "sendscore"
    }
}

/// Finds the CLI: `SENDSCORE_BIN`, then `PATH`, then the cache, then a download.
pub fn find_binary() -> Result<PathBuf, Error> {
    if let Some(path) = env::var_os("SENDSCORE_BIN").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    if let Some(path) = env::var_os("PATH") {
        for dir in env::split_paths(&path) {
            let candidate = dir.join(exe_name());
            if executable(&candidate) {
                return Ok(candidate);
            }
        }
    }
    let dir = cache_root()
        .ok_or_else(|| fail("no user cache directory".into()))?
        .join("sendscore")
        .join(ENGINE_VERSION);
    let cached = dir.join(exe_name());
    if executable(&cached) {
        return Ok(cached);
    }
    let (os, arch) = platform()?;
    let base = format!("{RELEASES}/v{ENGINE_VERSION}");
    download(ENGINE_VERSION, &base, &dir, os, arch)
}

fn fetch(url: &str) -> Result<Vec<u8>, Error> {
    let res = ureq::get(url)
        .call()
        .map_err(|e| fail(format!("download of {url} failed: {e}")))?;
    let mut body = Vec::new();
    res.into_reader()
        .take(MAX_DOWNLOAD)
        .read_to_end(&mut body)
        .map_err(|e| fail(format!("download of {url} failed: {e}")))?;
    Ok(body)
}

fn expected_hash(checksums: &str, name: &str) -> Result<String, Error> {
    checksums
        .lines()
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            let hash = parts.next()?;
            (parts.next()? == name).then(|| hash.to_ascii_lowercase())
        })
        .ok_or_else(|| fail(format!("checksums.txt does not list {name}")))
}

// One file, by its exact name, so no path in the archive is ever used.
fn extract(archive: &[u8], os: &str, name: &str) -> Result<Option<Vec<u8>>, Error> {
    let bad = |e: std::io::Error| fail(format!("could not read the archive: {e}"));
    let mut out = Vec::new();
    if os == "windows" {
        let mut zip = zip::ZipArchive::new(Cursor::new(archive))
            .map_err(|e| fail(format!("could not read the archive: {e}")))?;
        let result = zip.by_name(name);
        return match result {
            Ok(mut file) => {
                file.read_to_end(&mut out).map_err(bad)?;
                Ok(Some(out))
            }
            Err(_) => Ok(None),
        };
    }
    let mut tar = tar::Archive::new(GzDecoder::new(archive));
    for entry in tar.entries().map_err(bad)? {
        let mut entry = entry.map_err(bad)?;
        let matches = entry.path_bytes().as_ref() == name.as_bytes();
        if matches && entry.header().entry_type().is_file() {
            entry.read_to_end(&mut out).map_err(bad)?;
            return Ok(Some(out));
        }
    }
    Ok(None)
}

/// Downloads a release into `dir`, and returns the binary's path. The archive
/// is checked against `checksums.txt` before anything is extracted, so a
/// binary that does not match never reaches the disk.
#[doc(hidden)]
pub fn download(version: &str, base: &str, dir: &Path, os: &str, arch: &str) -> Result<PathBuf, Error> {
    let exe = if os == "windows" { "sendscore.exe" } else { "sendscore" };
    let ext = if os == "windows" { "zip" } else { "tar.gz" };
    let name = format!("sendscore_{version}_{os}_{arch}.{ext}");
    let checksums = String::from_utf8_lossy(&fetch(&format!("{base}/checksums.txt"))?).into_owned();
    let archive = fetch(&format!("{base}/{name}"))?;
    let actual: String = Sha256::digest(&archive).iter().map(|b| format!("{b:02x}")).collect();
    if actual != expected_hash(&checksums, &name)? {
        return Err(fail(format!("{name} does not match checksums.txt")));
    }
    let binary = extract(&archive, os, exe)?.ok_or_else(|| fail(format!("{name} has no {exe}")))?;
    let write = |e: std::io::Error| fail(format!("could not write to {}: {e}", dir.display()));
    fs::create_dir_all(dir).map_err(write)?;
    let temp = dir.join(format!(".download-{}", std::process::id()));
    fs::write(&temp, binary).map_err(write)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o755)).map_err(write)?;
    }
    let path = dir.join(exe);
    fs::rename(&temp, &path).map_err(|e| {
        let _ = fs::remove_file(&temp);
        write(e)
    })?;
    Ok(path)
}
