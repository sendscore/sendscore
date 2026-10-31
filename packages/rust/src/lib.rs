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
mod types;

pub use download::{download as download_release, find_binary, ENGINE_VERSION};
pub use types::*;

use serde::de::DeserializeOwned;
use std::ffi::OsString;
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// The CLI could not produce a report, or could not be found or installed.
#[derive(Debug, Clone)]
pub struct Error {
    pub message: String,
    /// The CLI's exit code: 64 and above, or 0 when the CLI never ran.
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
}

fn run(args: &[OsString], stdin: Option<&[u8]>) -> Result<Output, Error> {
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
    // Written on a thread so a full output pipe cannot deadlock against stdin.
    std::thread::scope(|s| {
        if let (Some(bytes), Some(mut pipe)) = (stdin, child.stdin.take()) {
            s.spawn(move || {
                let _ = pipe.write_all(bytes);
            });
        }
        child.wait_with_output().map_err(could_not)
    })
}

fn parse<T: DeserializeOwned>(out: Output, verdict_codes: &[i32]) -> Result<T, Error> {
    let code = out.status.code().unwrap_or(-1);
    if !verdict_codes.contains(&code) {
        let text = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let message = if text.is_empty() { format!("sendscore exited {code}") } else { text };
        return Err(Error { message, exit_code: code });
    }
    serde_json::from_slice(&out.stdout).map_err(|e| Error {
        message: format!("sendscore printed something this package cannot read: {e}"),
        exit_code: code,
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
        args.push(previous.into());
    }
    args.push("--".into());
    let stdin = match message.into() {
        Input::Path(path) => {
            args.push(path.into());
            None
        }
        Input::Bytes(bytes) => {
            args.push("-".into());
            Some(bytes)
        }
    };
    parse(run(&args, stdin)?, &[0, 1, 2])
}

/// Compares two saved messages.
pub fn diff(before: impl AsRef<Path>, after: impl AsRef<Path>) -> Result<DiffResult, Error> {
    let args: Vec<OsString> = vec![
        "diff".into(),
        "--json".into(),
        "--".into(),
        before.as_ref().into(),
        after.as_ref().into(),
    ];
    parse(run(&args, None)?, &[0, 1])
}
