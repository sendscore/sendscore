use sendscore::download_release;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

static NEXT: AtomicU32 = AtomicU32::new(0);

fn serve() -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/release");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            let _ = reader.read_line(&mut line);
            let path = line.split_whitespace().nth(1).unwrap_or("/").trim_start_matches('/').to_string();
            let mut stream = reader.into_inner();
            let reply: Vec<u8> = match fs::read(root.join(path)) {
                Ok(body) => {
                    let mut r = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
                    r.extend(body);
                    r
                }
                Err(_) => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
            };
            let _ = stream.write_all(&reply);
        }
    });
    base
}

fn tmp() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sendscore-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst)));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn names(dir: &Path) -> Vec<String> {
    fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect()
}

#[test]
fn installs_the_binary_and_nothing_else() {
    let base = serve();
    for (os, arch) in [("linux", "amd64"), ("darwin", "arm64"), ("windows", "amd64")] {
        let tmp = tmp();
        let cache = tmp.join("cache");
        let path = download_release("0.0.0-test", &format!("{base}/good"), &cache, os, arch).unwrap();
        assert!(String::from_utf8_lossy(&fs::read(&path).unwrap()).contains("fake sendscore"));
        assert_eq!(names(&cache), vec![path.file_name().unwrap().to_string_lossy().into_owned()]);
        assert!(!tmp.join("evil").exists());
    }
}

#[test]
fn refuses_a_mismatch() {
    let base = serve();
    let cache = tmp().join("cache");
    assert!(download_release("0.0.0-test", &format!("{base}/tampered"), &cache, "linux", "amd64").is_err());
    assert!(!cache.exists());
}

#[test]
fn fails_on_a_missing_release() {
    let base = serve();
    let cache = tmp().join("cache");
    assert!(download_release("0.0.0-test", &format!("{base}/nothing"), &cache, "linux", "amd64").is_err());
}
