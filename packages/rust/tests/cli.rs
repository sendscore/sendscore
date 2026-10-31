//! Each test sets process-wide environment, so they run one at a time.

use sendscore::{check, diff_with, find_binary, CheckOptions, DiffOptions, ENGINE_VERSION, KILLED};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

static LOCK: Mutex<()> = Mutex::new(());
static BUILT: OnceLock<PathBuf> = OnceLock::new();

const EXE: &str = if cfg!(windows) { "sendscore.exe" } else { "sendscore" };

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

fn sample() -> PathBuf {
    repo().join("conformance/messages/clean.eml")
}

fn tmp() -> PathBuf {
    let dir = env::temp_dir().join(format!("sendscore-cli-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn fake(mode: &str) -> PathBuf {
    let built = BUILT.get_or_init(|| {
        let out = tmp().join("built").join(EXE);
        let status = Command::new("go")
            .args(["build", "-o"])
            .arg(&out)
            .arg("./conformance/fakecli")
            .current_dir(repo())
            .status()
            .unwrap();
        assert!(status.success());
        out
    });
    let dir = tmp().join(mode);
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join(EXE);
    if !path.exists() {
        fs::copy(built, &path).unwrap();
    }
    path
}

fn only_path(path: &std::ffi::OsStr) {
    env::remove_var("SENDSCORE_BIN");
    env::set_var("PATH", path);
    env::set_var("HOME", tmp().join("home"));
    env::set_var("XDG_CACHE_HOME", tmp().join("cache"));
}

struct Restore(Vec<(&'static str, Option<std::ffi::OsString>)>);

impl Drop for Restore {
    fn drop(&mut self) {
        for (key, value) in &self.0 {
            match value {
                Some(v) => env::set_var(key, v),
                None => env::remove_var(key),
            }
        }
    }
}

fn guard() -> (std::sync::MutexGuard<'static, ()>, Restore) {
    let lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved = ["SENDSCORE_BIN", "PATH", "HOME", "XDG_CACHE_HOME"].map(|k| (k, env::var_os(k)));
    (lock, Restore(saved.into()))
}

#[test]
fn a_timeout_kills_the_cli() {
    let _g = guard();
    env::set_var("SENDSCORE_BIN", fake("hang"));
    let t = Some(Duration::from_millis(200));
    let e = check(sample().as_path(), &CheckOptions { timeout: t, ..Default::default() }).unwrap_err();
    assert_eq!(e.exit_code, KILLED);
    let e = diff_with(sample(), sample(), &DiffOptions { timeout: t }).unwrap_err();
    assert_eq!(e.exit_code, KILLED);
}

#[cfg(unix)]
#[test]
fn a_killed_cli_has_one_exit_code() {
    let _g = guard();
    env::set_var("SENDSCORE_BIN", fake("killed"));
    assert_eq!(check(sample().as_path(), &CheckOptions::default()).unwrap_err().exit_code, KILLED);
}

#[test]
fn output_that_is_not_a_verdict_is_refused() {
    let _g = guard();
    env::set_var("SENDSCORE_BIN", fake("planted"));
    assert!(check(sample().as_path(), &CheckOptions::default()).is_err());
    assert!(sendscore::diff(sample(), sample()).is_err());
}

#[test]
fn unknown_fields_and_stderr_are_tolerated() {
    let _g = guard();
    env::set_var("SENDSCORE_BIN", fake("noisy"));
    let got = check(sample().as_path(), &CheckOptions::default()).unwrap();
    assert!(got.ready_to_send);
    assert_eq!(got.checks.len(), 1);
}

#[test]
fn a_wrong_version_on_path_is_not_run() {
    let _g = guard();
    let path = fake("version-9.9.9");
    only_path(path.parent().unwrap().as_os_str());
    assert!(find_binary().unwrap_err().message.contains("no pinned hash"));
}

#[test]
fn the_pinned_version_on_path_is_used() {
    let _g = guard();
    let path = fake(&format!("version-{ENGINE_VERSION}"));
    only_path(path.parent().unwrap().as_os_str());
    assert_eq!(find_binary().unwrap(), path);
}

#[test]
fn relative_path_entries_are_skipped() {
    let _g = guard();
    let name = format!("version-{ENGINE_VERSION}");
    let path = fake(&name);
    fs::create_dir_all(&name).unwrap();
    fs::copy(&path, Path::new(&name).join(EXE)).unwrap();
    let joined = env::join_paths([PathBuf::new(), PathBuf::from(&name)]).unwrap();
    only_path(&joined);
    let found = find_binary();
    fs::remove_dir_all(&name).unwrap();
    assert!(found.unwrap_err().message.contains("no pinned hash"));
}

#[test]
fn paths_that_look_like_flags_are_files() {
    let _g = guard();
    let real = env::var_os("SENDSCORE_BIN").unwrap_or_else(|| repo().join("bin").join(EXE).into());
    env::set_var("SENDSCORE_BIN", real);
    let opts = CheckOptions { offline: true, ..Default::default() };
    for name in ["-", "-dash.eml"] {
        fs::copy(sample(), name).unwrap();
        let got = check(Path::new(name), &opts);
        fs::remove_file(name).unwrap();
        assert!(!got.unwrap().message.subject.is_empty());
    }
}
