//! End-to-end smoke test: spawn the binary with --dry-run, confirm
//! events.jsonl gets populated with the expected synthetic sequence.

use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::Command;

fn binary_path() -> std::path::PathBuf {
    // cargo sets CARGO_BIN_EXE_<name> for integration tests.
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_portsnatcher"))
}

#[tokio::test]
async fn dry_run_emits_full_event_sequence_to_jsonl() {
    let tmp = tempfile::tempdir().unwrap();
    let artifacts = tmp.path().join("artifacts");

    let mut cmd = Command::new(binary_path());
    cmd.arg("--dry-run")
        .arg("--bus-listen")
        .arg("127.0.0.1:0")
        .arg("--artifacts-dir")
        .arg(&artifacts)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = cmd.spawn().expect("spawn portsnatcher");

    // Wait for the process to exit (dry-run self-terminates quickly).
    let status = tokio::time::timeout(Duration::from_secs(15), child.wait())
        .await
        .expect("dry-run did not exit within 15s")
        .expect("wait failed");

    // Always drain stderr so test failures include the binary's logs.
    let mut stderr = String::new();
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut stderr).await;
    }
    assert!(
        status.success(),
        "portsnatcher --dry-run exited with {status:?}\nstderr:\n{stderr}"
    );

    let jsonl = artifacts.join("events.jsonl");
    let raw = tokio::fs::read_to_string(&jsonl)
        .await
        .unwrap_or_else(|e| panic!("read {jsonl:?}: {e}\nstderr:\n{stderr}"));
    let lines: Vec<&str> = raw.lines().collect();
    assert!(
        lines.len() >= 5,
        "expected at least 5 events (started + 3 catches * triple + finished); got {}\n{raw}",
        lines.len()
    );

    // Parse each line — they all must round-trip.
    for line in &lines {
        let _: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("bad JSON line: {e}\n{line}"));
    }

    // First event is EngagementStarted, last is EngagementFinished.
    let first: serde_json::Value = serde_json::from_str(lines.first().unwrap()).unwrap();
    assert_eq!(first["type"].as_str(), Some("EngagementStarted"));
    let last: serde_json::Value = serde_json::from_str(lines.last().unwrap()).unwrap();
    assert_eq!(last["type"].as_str(), Some("EngagementFinished"));

    // Every event shares the same engagement_id.
    let eid = first["engagement_id"].as_str().unwrap().to_owned();
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["engagement_id"].as_str(), Some(eid.as_str()));
        assert_eq!(v["schema"].as_str(), Some("portsnatcher/v1"));
    }
}
