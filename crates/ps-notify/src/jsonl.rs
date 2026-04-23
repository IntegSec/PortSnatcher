//! JSONL sink: append-only line-per-event log file.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use ps_core::event::Event;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::sink::EventSink;

#[derive(Debug)]
pub struct JsonlSink {
    path: PathBuf,
    file: Arc<Mutex<tokio::fs::File>>,
}

impl JsonlSink {
    pub async fn open(path: PathBuf) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.ok();
        }
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;
        Ok(Self {
            path,
            file: Arc::new(Mutex::new(file)),
        })
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

#[async_trait]
impl EventSink for JsonlSink {
    fn name(&self) -> &'static str {
        "jsonl"
    }

    async fn emit(&self, event: &Event) {
        let line = match serde_json::to_string(event) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("jsonl serialize failed: {e:#}");
                return;
            }
        };
        let mut file = self.file.lock().await;
        if let Err(e) = file.write_all(line.as_bytes()).await {
            tracing::error!("jsonl write failed: {e:#}");
            return;
        }
        if let Err(e) = file.write_all(b"\n").await {
            tracing::error!("jsonl write failed: {e:#}");
            return;
        }
        let _ = file.flush().await;
    }
}
