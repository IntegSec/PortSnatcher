//! JSONL sink integration test: write events, read them back, assert order.

use ps_core::event::payload::{EngagementStarted, EventBody};
use ps_core::event::Event;
use ps_core::id::EngagementId;
use ps_notify::sink::EventSink;
use ps_notify::JsonlSink;

fn ev(profile: &str) -> Event {
    Event::new(
        EngagementId::new(),
        None,
        EventBody::EngagementStarted(EngagementStarted {
            profile: profile.into(),
            engine: "connect".into(),
            targets: vec![],
            ports: "all".into(),
            rate_cap_pps: 0,
            dry_run: false,
        }),
    )
}

#[tokio::test]
async fn writes_one_line_per_event_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    let sink = JsonlSink::open(path.clone()).await.unwrap();

    let labels = ["a", "b", "c"];
    for label in labels.iter() {
        sink.emit(&ev(label)).await;
    }
    drop(sink); // ensure file is closed before re-reading

    let raw = tokio::fs::read_to_string(&path).await.unwrap();
    let lines: Vec<&str> = raw.lines().collect();
    assert_eq!(lines.len(), labels.len());
    for (line, expected) in lines.iter().zip(labels.iter()) {
        let parsed: Event = serde_json::from_str(line).expect("each line is a valid Event");
        // Pull profile out of the body via JSON value.
        let val = serde_json::to_value(&parsed.body).unwrap();
        let profile = val
            .get("payload")
            .and_then(|p| p.get("profile"))
            .and_then(|p| p.as_str())
            .unwrap();
        assert_eq!(profile, *expected);
    }
}
