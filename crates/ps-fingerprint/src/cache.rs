//! Per-engagement fingerprint cache.
//!
//! Keys are `(IpAddr, port)`. Because JSON map keys must be strings,
//! the on-disk representation flattens the key into `"ip:port"` form
//! (e.g. `"127.0.0.1:443"`, `"[::1]:443"` for IPv6) and restores the
//! typed key on load.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use serde::Serialize;
use tokio::sync::RwLock;

use crate::report::FingerprintReport;
use ps_core::target::Target;

/// `(IpAddr, port)` cache key.
type Key = (IpAddr, u16);

/// Cache of per-`(IpAddr, port)` fingerprint reports.
///
/// The in-memory map uses the typed `Key` for lookup efficiency; the
/// on-disk JSON uses the `"ip:port"` string form because JSON forbids
/// non-string map keys. `flush()` is crash-safe via a temp-file rename.
#[derive(Debug, Clone)]
pub struct FingerprintCache {
    path: PathBuf,
    inner: Arc<RwLock<HashMap<Key, FingerprintReport>>>,
}

impl FingerprintCache {
    /// Create an empty cache rooted at `path`. The file is not touched
    /// until the first `flush()` call.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Load the cache from `path`. Missing file => empty cache (this is
    /// the common case on first engagement run).
    pub async fn load(path: PathBuf) -> Result<Self, CacheError> {
        let inner: HashMap<Key, FingerprintReport> = if path.exists() {
            let raw = tokio::fs::read(&path).await?;
            let stringly: HashMap<String, FingerprintReport> = serde_json::from_slice(&raw)?;
            let mut parsed = HashMap::with_capacity(stringly.len());
            for (k, v) in stringly {
                let key = parse_key(&k).ok_or_else(|| CacheError::BadKey(k.clone()))?;
                parsed.insert(key, v);
            }
            parsed
        } else {
            HashMap::new()
        };
        Ok(Self {
            path,
            inner: Arc::new(RwLock::new(inner)),
        })
    }

    /// Look up a cached report for `target`.
    pub async fn get(&self, target: &Target) -> Option<FingerprintReport> {
        self.inner
            .read()
            .await
            .get(&(target.ip, target.port))
            .cloned()
    }

    /// Insert or overwrite the report for `target`.
    pub async fn insert(&self, target: Target, report: FingerprintReport) {
        self.inner
            .write()
            .await
            .insert((target.ip, target.port), report);
    }

    /// Persist the cache atomically by writing to a sibling `*.tmp`
    /// file and then renaming over the destination.
    pub async fn flush(&self) -> Result<(), CacheError> {
        let snap = self.inner.read().await.clone();
        let stringly: HashMap<String, FingerprintReport> =
            snap.into_iter().map(|(k, v)| (format_key(k), v)).collect();
        let raw = serde_json::to_vec_pretty(&StringlyMap(&stringly))?;
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await?;
            }
        }
        let tmp = self.path.with_extension("json.tmp");
        tokio::fs::write(&tmp, &raw).await?;
        tokio::fs::rename(&tmp, &self.path).await?;
        Ok(())
    }
}

/// Wrapper so we serialize the `HashMap<String, _>` transparently.
/// Only `Serialize` is needed — the read path uses `HashMap<String, _>`
/// directly.
#[derive(Serialize)]
#[serde(transparent)]
struct StringlyMap<'a>(&'a HashMap<String, FingerprintReport>);

fn format_key(key: Key) -> String {
    match key.0 {
        IpAddr::V4(v4) => format!("{v4}:{}", key.1),
        IpAddr::V6(v6) => format!("[{v6}]:{}", key.1),
    }
}

fn parse_key(s: &str) -> Option<Key> {
    // IPv6 form: "[::1]:443"
    if let Some(rest) = s.strip_prefix('[') {
        let (ip_part, port_part) = rest.split_once("]:")?;
        let ip: IpAddr = ip_part.parse().ok()?;
        let port: u16 = port_part.parse().ok()?;
        return Some((ip, port));
    }
    // IPv4 form: "127.0.0.1:443"
    let (ip_part, port_part) = s.rsplit_once(':')?;
    let ip: IpAddr = ip_part.parse().ok()?;
    let port: u16 = port_part.parse().ok()?;
    Some((ip, port))
}

/// Errors returned by `FingerprintCache` IO.
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    /// Filesystem error reading/writing the cache file.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// JSON (de)serialization error.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// On-disk key could not be parsed back into `(IpAddr, port)`.
    #[error("bad cache key: {0}")]
    BadKey(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::Protocol;
    use crate::report::{FingerprintReport, ProbeRunRecord};
    use bytes::Bytes;
    use ps_core::id::CatchId;
    use std::path::PathBuf;

    fn sample(catch: CatchId) -> FingerprintReport {
        FingerprintReport {
            catch_id: catch,
            protocol_guess: Some(Protocol::Http11),
            confidence: 0.95,
            banner_excerpt: Bytes::from_static(b"HTTP/1.1 200 OK\r\n"),
            tls_info: None,
            probes_run: vec![ProbeRunRecord {
                probe: "http_head",
                outcome: "match",
                bytes_captured: 17,
                duration_ms: 23,
            }],
            artifacts_path: PathBuf::from("/tmp/x"),
        }
    }

    #[tokio::test]
    async fn insert_flush_reload_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fp.json");
        let target = Target::new("10.0.0.5".parse().unwrap(), 443);
        let cache = FingerprintCache::new(path.clone());
        cache.insert(target.clone(), sample(CatchId::new())).await;
        cache.flush().await.unwrap();

        let reloaded = FingerprintCache::load(path).await.unwrap();
        let got = reloaded.get(&target).await.expect("entry should reload");
        assert_eq!(got.protocol_guess, Some(Protocol::Http11));
        assert!((got.confidence - 0.95).abs() < 1e-6);
    }

    #[tokio::test]
    async fn get_returns_none_for_missing_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fp.json");
        let cache = FingerprintCache::new(path);
        let target = Target::new("10.0.0.7".parse().unwrap(), 80);
        assert!(cache.get(&target).await.is_none());
    }

    #[tokio::test]
    async fn ipv6_key_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fp.json");
        let target = Target::new("::1".parse().unwrap(), 443);
        let cache = FingerprintCache::new(path.clone());
        cache.insert(target.clone(), sample(CatchId::new())).await;
        cache.flush().await.unwrap();
        let reloaded = FingerprintCache::load(path).await.unwrap();
        assert!(reloaded.get(&target).await.is_some());
    }
}
