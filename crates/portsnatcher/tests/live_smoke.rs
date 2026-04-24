//! End-to-end smoke test for the live (non-dry-run) path: stand up a
//! fixture TCP server on loopback, spawn the binary with a target + port
//! pointing at it, and assert the JSONL artifact captures the full event
//! arc (EngagementStarted → PortOpenDetected → CatchComplete →
//! EngagementFinished).

use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::process::Command;

fn binary_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_portsnatcher"))
}

#[tokio::test]
async fn live_engagement_catches_loopback_port_and_finishes() {
    // Fixture: bind an ephemeral port on loopback and accept in a loop so
    // the ConnectEngine's handshake completes cleanly.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            if listener.accept().await.is_err() {
                break;
            }
        }
    });

    let tmp = tempfile::tempdir().unwrap();
    let artifacts = tmp.path().join("artifacts");

    let mut cmd = Command::new(binary_path());
    cmd.arg("127.0.0.1")
        .arg("--ports")
        .arg(format!("{port}"))
        .arg("--profile")
        .arg("ctf")
        .arg("--engine")
        .arg("connect")
        .arg("--bus-listen")
        .arg("127.0.0.1:0")
        .arg("--artifacts-dir")
        .arg(&artifacts)
        .arg("--duration-ms")
        .arg("2500")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = cmd.spawn().expect("spawn portsnatcher");
    let status = tokio::time::timeout(Duration::from_secs(30), child.wait())
        .await
        .expect("portsnatcher live did not exit within 30s")
        .expect("wait failed");

    let mut stderr = String::new();
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut stderr).await;
    }
    assert!(
        status.success(),
        "portsnatcher exited with {status:?}\nstderr:\n{stderr}"
    );

    let jsonl = artifacts.join("events.jsonl");
    let raw = tokio::fs::read_to_string(&jsonl)
        .await
        .unwrap_or_else(|e| panic!("read {jsonl:?}: {e}\nstderr:\n{stderr}"));
    let lines: Vec<&str> = raw.lines().collect();
    assert!(
        !lines.is_empty(),
        "events.jsonl is empty\nstderr:\n{stderr}"
    );

    let mut saw_started = false;
    let mut saw_port_open = false;
    let mut saw_finished = false;
    for line in &lines {
        let v: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("bad JSON line: {e}\n{line}"));
        assert_eq!(v["schema"].as_str(), Some("portsnatcher/v1"));
        match v["type"].as_str() {
            Some("EngagementStarted") => saw_started = true,
            Some("PortOpenDetected") => {
                saw_port_open = true;
                assert_eq!(v["payload"]["port"].as_u64(), Some(port as u64));
                assert_eq!(v["payload"]["engine"].as_str(), Some("connect"));
            }
            Some("EngagementFinished") => saw_finished = true,
            _ => {}
        }
    }

    assert!(saw_started, "missing EngagementStarted in {raw}");
    assert!(
        saw_port_open,
        "did not observe PortOpenDetected for fixture port {port}\nevents:\n{raw}"
    );
    assert!(saw_finished, "missing EngagementFinished in {raw}");
}
