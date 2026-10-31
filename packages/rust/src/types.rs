//! The `sendscore.verdict/v1` report. Fields this version does not know are
//! ignored, since the schema may add them.

use serde::{Deserialize, Deserializer};
use serde_json::Value;
use std::collections::HashMap;

fn null_is_empty<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

/// The outcome of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Warn,
    Fail,
    Info,
    Skipped,
    #[serde(other)]
    Other,
}

/// The group a check belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Auth,
    Unsub,
    Struct,
    Content,
    Delivery,
    Changes,
    #[serde(other)]
    Other,
}

/// What was checked.
#[derive(Debug, Clone, Deserialize)]
pub struct Message {
    pub received_at: String,
    pub from: String,
    pub subject: String,
    pub message_id: String,
    pub size_bytes: u64,
}

/// What to change, and who can change it (`you` or `provider`).
#[derive(Debug, Clone, Deserialize)]
pub struct Fix {
    pub who: String,
    pub text: String,
}

/// One rule applied to the message, with the evidence it looked at.
#[derive(Debug, Clone, Deserialize)]
pub struct Check {
    pub id: String,
    pub category: Category,
    pub status: Status,
    pub title: String,
    pub detail: Option<String>,
    pub evidence: Option<HashMap<String, Value>>,
    pub fix: Option<Fix>,
    pub docs: Option<String>,
    /// Why the check was skipped.
    pub reason: Option<String>,
}

/// One of the fixes to make first.
#[derive(Debug, Clone, Deserialize)]
pub struct TopFix {
    pub check: String,
    pub who: String,
    pub fix: String,
}

/// One difference from the previous issue.
#[derive(Debug, Clone, Deserialize)]
pub struct Change {
    pub field: String,
    pub before: Value,
    pub after: Value,
    /// The check this change made worse, if any.
    pub worsened: Option<String>,
}

/// What the comparison looks at.
#[derive(Debug, Clone, Deserialize)]
pub struct Fingerprint {
    #[serde(default, deserialize_with = "null_is_empty")]
    pub dkim_domains: Vec<String>,
    #[serde(default, deserialize_with = "null_is_empty")]
    pub dkim_selectors: Vec<String>,
    pub return_path_domain: String,
    pub remote_ip: Option<String>,
    pub ptr: Option<String>,
    pub list_unsubscribe: bool,
    pub one_click: bool,
    #[serde(default, deserialize_with = "null_is_empty")]
    pub link_hosts: Vec<String>,
    pub html_bytes: u64,
    pub links: u64,
    pub images: u64,
    pub auth: Option<HashMap<String, Status>>,
}

/// The full report for one message.
#[derive(Debug, Clone, Deserialize)]
pub struct Verdict {
    pub schema: String,
    pub id: Option<String>,
    pub message: Message,
    pub publication: Option<String>,
    pub verdict: Status,
    pub ready_to_send: bool,
    pub summary: String,
    #[serde(default, deserialize_with = "null_is_empty")]
    pub top_fixes: Vec<TopFix>,
    #[serde(default, deserialize_with = "null_is_empty")]
    pub checks: Vec<Check>,
    #[serde(default, deserialize_with = "null_is_empty")]
    pub changes: Vec<Change>,
    pub fingerprint: Option<Fingerprint>,
    pub explanation: Option<String>,
    pub note: String,
}

/// The differences between two saved messages.
#[derive(Debug, Clone, Deserialize)]
pub struct DiffResult {
    pub before: String,
    pub after: String,
    #[serde(default, deserialize_with = "null_is_empty")]
    pub changes: Vec<Change>,
}
