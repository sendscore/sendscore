//! Finds the CLI, and downloads a release when none is installed.

use crate::hashes::HASHES;
use crate::Error;
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// The CLI release this crate downloads when none is installed.
pub const ENGINE_VERSION: &str = "0.3.0";
const RELEASES: &str = "https://github.com/sendscore/sendscore/releases/download";
const MAX_DOWNLOAD: u64 = 100 << 20;
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// The SHA-256 of a release archive and of the binary inside it.
#[derive(Debug, Clone, Copy)]
pub struct Pin<'a> {
    pub archive: &'a str,
    pub binary: &'a str,
}

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
            .filter(|p| p.is_absolute())
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

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// The pin for a platform. With none, nothing is downloaded or trusted.
pub(crate) fn pin_for(os: &str, arch: &str) -> Result<Pin<'static>, Error> {
    let key = format!("{os}_{arch}");
    HASHES
        .iter()
        .find(|(k, _, _)| *k == key)
        .map(|(_, archive, binary)| Pin { archive, binary })
        .ok_or_else(|| {
            fail(format!(
                "this package has no pinned hash for {key}, so it will not download a CLI. Install the matching sendscore on PATH, or set SENDSCORE_BIN."
            ))
        })
}

/// Whether a file exists and is exactly the pinned binary.
#[doc(hidden)]
pub fn matches_pin(path: &Path, pin: Pin<'_>) -> bool {
    fs::read(path).is_ok_and(|bytes| sha256(&bytes) == pin.binary)
}

fn right_version(path: &Path) -> bool {
    let Ok(mut child) = Command::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let mut out = String::new();
    if let Some(stdout) = child.stdout.take() {
        let _ = stdout.take(4096).read_to_string(&mut out);
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if std::time::Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    status.is_some_and(|s| s.success())
        && out.split_whitespace().last().is_some_and(|v| v.trim_start_matches('v') == ENGINE_VERSION)
}

/// Finds the CLI: `SENDSCORE_BIN`, then the pinned version on `PATH`, then the
/// cache, then a download. A cached binary is checked against its pinned hash
/// every time, so a file planted in the cache is replaced and never run.
pub fn find_binary() -> Result<PathBuf, Error> {
    if let Some(path) = env::var_os("SENDSCORE_BIN").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    if let Some(path) = env::var_os("PATH") {
        for dir in env::split_paths(&path).filter(|d| d.is_absolute()) {
            let candidate = dir.join(exe_name());
            if executable(&candidate) && right_version(&candidate) {
                return Ok(candidate);
            }
        }
    }
    let (os, arch) = platform()?;
    let pin = pin_for(os, arch)?;
    let dir = cache_root()
        .ok_or_else(|| fail("no user cache directory".into()))?
        .join("sendscore")
        .join(ENGINE_VERSION);
    let cached = dir.join(exe_name());
    if matches_pin(&cached, pin) {
        return Ok(cached);
    }
    let base = format!("{RELEASES}/v{ENGINE_VERSION}");
    download(ENGINE_VERSION, &base, &dir, os, arch, pin)
}

fn fetch(url: &str) -> Result<Vec<u8>, Error> {
    let agent = ureq::AgentBuilder::new().timeout(DOWNLOAD_TIMEOUT).build();
    let res = agent
        .get(url)
        .call()
        .map_err(|e| fail(format!("download of {url} failed: {e}")))?;
    let mut body = Vec::new();
    res.into_reader()
        .take(MAX_DOWNLOAD)
        .read_to_end(&mut body)
        .map_err(|e| fail(format!("download of {url} failed: {e}")))?;
    Ok(body)
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
/// must match its pin before anything is extracted, and the binary must match
/// its pin before it reaches the disk.
#[doc(hidden)]
pub fn download(version: &str, base: &str, dir: &Path, os: &str, arch: &str, pin: Pin<'_>) -> Result<PathBuf, Error> {
    let exe = if os == "windows" { "sendscore.exe" } else { "sendscore" };
    let ext = if os == "windows" { "zip" } else { "tar.gz" };
    let name = format!("sendscore_{version}_{os}_{arch}.{ext}");
    let archive = fetch(&format!("{base}/{name}"))?;
    if sha256(&archive) != pin.archive {
        return Err(fail(format!("{name} does not match its pinned hash")));
    }
    let binary = extract(&archive, os, exe)?.ok_or_else(|| fail(format!("{name} has no {exe}")))?;
    if sha256(&binary) != pin.binary {
        return Err(fail(format!("the binary in {name} does not match its pinned hash")));
    }
    let write = |e: std::io::Error| fail(format!("could not write to {}: {e}", dir.display()));
    fs::create_dir_all(dir).map_err(write)?;
    // Unique per call, so threads and processes never share a partial file.
    let temp = dir.join(format!(
        ".download-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    let installed = (|| {
        fs::write(&temp, &binary)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temp, fs::Permissions::from_mode(0o755))?;
        }
        let path = dir.join(exe);
        // On Windows a rename fails while another caller holds the target open.
        let mut attempts = 40;
        while let Err(e) = fs::rename(&temp, &path) {
            attempts -= 1;
            if attempts == 0 {
                return Err(e);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(path)
    })();
    if installed.is_err() {
        let _ = fs::remove_file(&temp);
    }
    installed.map_err(write)
}
