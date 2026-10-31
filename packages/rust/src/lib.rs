//! Check a newsletter email before it goes out, with the SendScore CLI.
//!
//! ```no_run
//! let verdict = sendscore::check("issue.eml", &Default::default())?;
//! if !verdict.ready_to_send {
//!     for fix in &verdict.top_fixes {
//!         println!("{} {}", fix.who, fix.fix);
//!     }
//! }
//! # Ok::<(), sendscore::Error>(())
//! ```

mod download;
mod hashes;
mod types;

pub use download::{download as download_release, find_binary, matches_pin, Pin, ENGINE_VERSION};
pub use types::*;

use serde::de::DeserializeOwned;
use std::ffi::OsString;
use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The `exit_code` of a CLI that was killed, or stopped by a timeout.
pub const KILLED: i32 = -1;

/// The CLI could not produce a report, or could not be found or installed.
#[derive(Debug, Clone)]
pub struct Error {
    pub message: String,
    /// The CLI's exit code: 64 and above, 0 when the CLI never ran, or `KILLED`.
    pub exit_code: i32,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

/// A message to check: a path, or its bytes.
#[derive(Debug, Clone, Copy)]
pub enum Input<'a> {
    Path(&'a Path),
    Bytes(&'a [u8]),
}

impl<'a> From<&'a str> for Input<'a> {
    fn from(path: &'a str) -> Self {
        Input::Path(Path::new(path))
    }
}

impl<'a> From<&'a Path> for Input<'a> {
    fn from(path: &'a Path) -> Self {
        Input::Path(path)
    }
}

impl<'a> From<&'a PathBuf> for Input<'a> {
    fn from(path: &'a PathBuf) -> Self {
        Input::Path(path)
    }
}

impl<'a> From<&'a [u8]> for Input<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        Input::Bytes(bytes)
    }
}

/// What `check` should do beyond reading the message.
#[derive(Debug, Clone, Default)]
pub struct CheckOptions {
    /// Make no DNS lookups. Checks that need DNS are skipped.
    pub offline: bool,
    /// Fetch every link and image, never unsubscribe or confirm links.
    pub links: bool,
    /// IP address of the server that delivered the message.
    pub ip: Option<String>,
    /// Envelope sender. Defaults to the Return-Path.
    pub mail_from: Option<String>,
    /// HELO name the delivering server gave.
    pub helo: Option<String>,
    /// Whether delivery used TLS.
    pub tls: Option<bool>,
    /// Path of the publication's previous issue, to list what changed.
    pub previous: Option<PathBuf>,
    /// Kill the CLI and return an error after this long. No limit by default.
    pub timeout: Option<Duration>,
}

/// What `diff_with` should do beyond reading the messages.
#[derive(Debug, Clone, Default)]
pub struct DiffOptions {
    /// Kill the CLI and return an error after this long. No limit by default.
    pub timeout: Option<Duration>,
}

/// A lone `-` would mean standard input to the CLI.
fn path_arg(path: &Path) -> OsString {
    if path == Path::new("-") {
        "./-".into()
    } else {
        path.into()
    }
}

struct Finished {
    code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run(args: &[OsString], stdin: Option<&[u8]>, timeout: Option<Duration>) -> Result<Finished, Error> {
    let binary = find_binary()?;
    let could_not = |e: std::io::Error| Error {
        message: format!("could not run {}: {e}", binary.display()),
        exit_code: 0,
    };
    let mut child = Command::new(&binary)
        .args(args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(could_not)?;
    let input = child.stdin.take();
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let deadline = timeout.map(|t| Instant::now() + t);
    // Pipes are served on threads, so a full one cannot deadlock against another.
    std::thread::scope(|s| {
        if let (Some(bytes), Some(mut pipe)) = (stdin, input) {
            s.spawn(move || {
                let _ = pipe.write_all(bytes);
            });
        }
        let out = s.spawn(move || {
            let mut buf = Vec::new();
            if let Some(pipe) = stdout.as_mut() {
                let _ = pipe.read_to_end(&mut buf);
            }
            buf
        });
        let err = s.spawn(move || {
            let mut buf = Vec::new();
            if let Some(pipe) = stderr.as_mut() {
                let _ = pipe.read_to_end(&mut buf);
            }
            buf
        });
        let status = loop {
            if let Some(status) = child.try_wait().map_err(could_not)? {
                break status;
            }
            if deadline.is_some_and(|d| Instant::now() >= d) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error {
                    message: "sendscore did not finish in time".into(),
                    exit_code: KILLED,
                });
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let code = status.code().filter(|c| (0..128).contains(c)).unwrap_or(KILLED);
        Ok(Finished {
            code,
            stdout: out.join().unwrap_or_default(),
            stderr: err.join().unwrap_or_default(),
        })
    })
}

fn parse<T: DeserializeOwned>(out: Finished, verdict_codes: &[i32]) -> Result<T, Error> {
    let code = out.code;
    if !verdict_codes.contains(&code) {
        let text = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let message = if text.is_empty() { format!("sendscore exited {code}") } else { text };
        return Err(Error { message, exit_code: code });
    }
    // A parse failure is not the CLI's verdict, so it reports no CLI exit code.
    serde_json::from_slice(&out.stdout).map_err(|e| Error {
        message: format!("sendscore printed something this package cannot read: {e}"),
        exit_code: 0,
    })
}

/// Checks one message. A message that fails checks is still a report: this
/// returns an error only when no report could be made.
pub fn check<'a>(message: impl Into<Input<'a>>, options: &CheckOptions) -> Result<Verdict, Error> {
    let mut args: Vec<OsString> = vec!["check".into(), "--json".into()];
    if options.offline {
        args.push("--offline".into());
    }
    if options.links {
        args.push("--links".into());
    }
    for (flag, value) in [
        ("--ip", &options.ip),
        ("--mail-from", &options.mail_from),
        ("--helo", &options.helo),
    ] {
        if let Some(value) = value {
            args.push(flag.into());
            args.push(value.into());
        }
    }
    if let Some(tls) = options.tls {
        args.push("--tls".into());
        args.push(if tls { "yes" } else { "no" }.into());
    }
    if let Some(previous) = &options.previous {
        args.push("--previous".into());
        args.push(path_arg(previous));
    }
    args.push("--".into());
    let stdin = match message.into() {
        Input::Path(path) => {
            args.push(path_arg(path));
            None
        }
        Input::Bytes(bytes) => {
            args.push("-".into());
            Some(bytes)
        }
    };
    let verdict: Verdict = parse(run(&args, stdin, options.timeout)?, &[0, 1, 2])?;
    if !verdict.schema.starts_with("sendscore.verdict/") {
        return Err(Error {
            message: "sendscore printed something that is not a verdict".into(),
            exit_code: 0,
        });
    }
    Ok(verdict)
}

/// Compares two saved messages.
pub fn diff(before: impl AsRef<Path>, after: impl AsRef<Path>) -> Result<DiffResult, Error> {
    diff_with(before, after, &DiffOptions::default())
}

/// Compares two saved messages, with options.
pub fn diff_with(before: impl AsRef<Path>, after: impl AsRef<Path>, options: &DiffOptions) -> Result<DiffResult, Error> {
    let args: Vec<OsString> = vec![
        "diff".into(),
        "--json".into(),
        "--".into(),
        path_arg(before.as_ref()),
        path_arg(after.as_ref()),
    ];
    parse(run(&args, None, options.timeout)?, &[0, 1])
}
