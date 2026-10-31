use sendscore::{check, diff, CheckOptions, Input, Status};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance")
}

fn text(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(String::from)
}

fn list(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

fn status_name(s: Status) -> &'static str {
    match s {
        Status::Pass => "pass",
        Status::Warn => "warn",
        Status::Fail => "fail",
        Status::Info => "info",
        Status::Skipped => "skipped",
        Status::Other => "other",
    }
}

#[test]
fn conformance() {
    let root = root();
    let file: Value = serde_json::from_slice(&std::fs::read(root.join("cases.json")).unwrap()).unwrap();
    for c in file["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let exit = c["exit"].as_i64().unwrap();
        if c["command"] == "diff" {
            let got = diff(root.join(c["before"].as_str().unwrap()), root.join(c["after"].as_str().unwrap()));
            match got {
                Err(e) => assert_eq!(i64::from(e.exit_code), exit, "{name}"),
                Ok(d) => {
                    assert!(exit <= 2, "{name}");
                    assert_eq!(d.changes.iter().map(|x| x.field.clone()).collect::<Vec<_>>(), list(c, "changes"), "{name}");
                    assert_eq!(d.changes.iter().filter_map(|x| x.worsened.clone()).collect::<Vec<_>>(), list(c, "worsened"), "{name}");
                }
            }
            continue;
        }
        let given = c.get("options").cloned().unwrap_or(Value::Null);
        let opts = CheckOptions {
            offline: true,
            ip: text(&given, "ip"),
            mail_from: text(&given, "mail_from"),
            helo: text(&given, "helo"),
            tls: given.get("tls").and_then(Value::as_bool),
            previous: text(&given, "previous").map(|p| root.join(p)),
            ..Default::default()
        };
        let path = root.join(c["message"].as_str().unwrap());
        let bytes;
        let input = if c["via"] == "stdin" {
            bytes = std::fs::read(&path).unwrap();
            Input::Bytes(&bytes)
        } else {
            Input::Path(&path)
        };
        match check(input, &opts) {
            Err(e) => assert_eq!(i64::from(e.exit_code), exit, "{name}"),
            Ok(v) => {
                assert!(exit <= 2, "{name}");
                assert_eq!(status_name(v.verdict), c["verdict"].as_str().unwrap(), "{name}");
                assert_eq!(v.ready_to_send, c["ready_to_send"].as_bool().unwrap(), "{name}");
                let got: HashMap<_, _> = v.checks.iter().map(|x| (x.id.as_str(), status_name(x.status))).collect();
                let want: HashMap<_, _> = c["checks"].as_object().unwrap().iter().map(|(k, s)| (k.as_str(), s.as_str().unwrap())).collect();
                assert_eq!(got, want, "{name}");
                assert_eq!(v.changes.iter().map(|x| x.field.clone()).collect::<Vec<_>>(), list(c, "changes"), "{name}");
                assert_eq!(v.changes.iter().filter_map(|x| x.worsened.clone()).collect::<Vec<_>>(), list(c, "worsened"), "{name}");
            }
        }
    }
}

#[test]
fn unknown_fields_are_ignored() {
    let raw = r#"{"schema":"sendscore.verdict/v1","message":{"received_at":"","from":"","subject":"","message_id":"","size_bytes":0,"new":1},"verdict":"pass","ready_to_send":true,"summary":"","top_fixes":[],"checks":[],"changes":null,"explanation":null,"note":"","new_field":{"a":1}}"#;
    let v: sendscore::Verdict = serde_json::from_str(raw).unwrap();
    assert!(v.ready_to_send);
    assert!(v.changes.is_empty());
}
