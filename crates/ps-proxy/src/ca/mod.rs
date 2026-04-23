//! PortSnatcher MITM certificate authority.
//!
//! The CA is generated once per install (ECDSA P-256, 10-year validity)
//! and stored under a platform-appropriate config dir — on Linux
//! `~/.config/portsnatcher/ca/`, on macOS
//! `~/Library/Application Support/portsnatcher/ca/`, on Windows
//! `%APPDATA%\portsnatcher\ca\`. See [`storage::default_dir`] for the
//! exact resolution logic.
//!
//! Three entry points:
//!
//! - [`Ca::new_or_load`] — idempotent: generates a CA on first call,
//!   reuses the existing one afterwards. The SHA-256 of the DER is
//!   written next to the key for the install / uninstall UX.
//! - [`Ca::sign_leaf`] — issues a 90-day ECDSA leaf for the requested
//!   hostname, signs it with the CA key, caches it in a bounded LRU,
//!   and returns a [`rustls::sign::CertifiedKey`] ready to plug into
//!   [`rustls::server::ResolvesServerCert`].
//! - [`trust`] — platform-specific trust-store install/uninstall.

mod generate;
pub mod storage;
pub mod trust;

use std::path::Path;
use std::sync::{Arc, Mutex};

use rustls::sign::CertifiedKey;

pub use generate::{generate_ca, sign_leaf_internal};

/// Maximum number of leaves cached in-memory per `Ca` instance.
///
/// The cache is keyed by hostname. At 128 distinct SNI hostnames a
/// single engagement is almost certainly covering unrelated targets
/// and re-signing is cheap enough to not matter.
pub const LEAF_CACHE_CAPACITY: usize = 128;

/// In-memory representation of the PortSnatcher MITM CA.
///
/// Build via [`Ca::new_or_load`]. Clone is cheap — all fields are
/// either small (`Vec<u8>`, `String`) or already behind an `Arc`.
pub struct Ca {
    /// DER-encoded CA certificate. The fingerprint is computed over
    /// this exact byte string.
    pub cert_der: Vec<u8>,
    /// PEM-encoded CA private key. Kept as a PEM string because rcgen
    /// round-trips through PEM when reconstructing an `Issuer`.
    pub key_pem: String,
    /// SHA-256 of `cert_der`, hex-encoded (lowercase, 64 chars).
    pub fingerprint_sha256: String,

    // Bounded LRU cache of `(hostname -> CertifiedKey)` so repeated
    // catches on the same upstream don't re-issue leaves.
    leaf_cache: Arc<Mutex<LruCache>>,
}

struct LruCache {
    entries: std::collections::VecDeque<(String, Arc<CertifiedKey>)>,
    cap: usize,
}

impl LruCache {
    fn new(cap: usize) -> Self {
        Self {
            entries: std::collections::VecDeque::with_capacity(cap),
            cap,
        }
    }

    fn get(&mut self, host: &str) -> Option<Arc<CertifiedKey>> {
        let pos = self.entries.iter().position(|(h, _)| h == host)?;
        let entry = self.entries.remove(pos).unwrap();
        let ck = entry.1.clone();
        self.entries.push_front(entry);
        Some(ck)
    }

    fn put(&mut self, host: String, ck: Arc<CertifiedKey>) {
        if self.entries.len() >= self.cap {
            self.entries.pop_back();
        }
        self.entries.push_front((host, ck));
    }
}

impl Ca {
    /// Load or generate the CA in `dir`.
    ///
    /// If `dir` contains `ca.crt` and `ca.key` they are loaded and the
    /// fingerprint is recomputed from the cert DER. Otherwise a fresh
    /// ECDSA P-256 self-signed CA is generated (CN
    /// `"PortSnatcher CA"`, 10-year validity, `keyCertSign + cRLSign`),
    /// written to `ca.crt` / `ca.key` (the key gets mode 0600 on
    /// Unix), and the fingerprint is written to
    /// `ca-fingerprint.sha256`.
    pub fn new_or_load(dir: &Path) -> anyhow::Result<Self> {
        let bundle = generate::generate_or_load(dir)?;
        Ok(Self {
            cert_der: bundle.cert_der,
            key_pem: bundle.key_pem,
            fingerprint_sha256: bundle.fingerprint_sha256,
            leaf_cache: Arc::new(Mutex::new(LruCache::new(LEAF_CACHE_CAPACITY))),
        })
    }

    /// Issue a 90-day leaf certificate for `hostname`, signed by this
    /// CA, and return it as a [`CertifiedKey`] for rustls.
    ///
    /// Cached in-memory keyed by `hostname`; repeated calls return the
    /// same `Arc` without re-signing.
    pub fn sign_leaf(&self, hostname: &str) -> anyhow::Result<Arc<CertifiedKey>> {
        // rustls signing helpers require a crypto provider. Idempotent.
        let _ = rustls::crypto::ring::default_provider().install_default();
        {
            let mut cache = self.leaf_cache.lock().unwrap();
            if let Some(ck) = cache.get(hostname) {
                return Ok(ck);
            }
        }
        let ck = Arc::new(generate::sign_leaf_internal(
            &self.cert_der,
            &self.key_pem,
            hostname,
        )?);
        {
            let mut cache = self.leaf_cache.lock().unwrap();
            cache.put(hostname.to_string(), ck.clone());
        }
        Ok(ck)
    }

    /// Structured fingerprint newtype with colon-separated display.
    pub fn fingerprint(&self) -> CaFingerprint {
        CaFingerprint(self.fingerprint_sha256.clone())
    }
}

/// Newtype wrapper over the hex SHA-256 fingerprint string.
///
/// `Display` formats as colon-separated pairs, matching the convention
/// used by `openssl x509 -fingerprint` and the platform UIs:
///
/// ```text
/// AB:CD:EF:...
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaFingerprint(pub String);

impl std::fmt::Display for CaFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = self.0.trim();
        let upper = hex.to_uppercase();
        let bytes = upper.as_bytes();
        let mut first = true;
        let mut i = 0;
        while i + 1 < bytes.len() {
            if !first {
                f.write_str(":")?;
            }
            f.write_str(std::str::from_utf8(&bytes[i..i + 2]).unwrap_or("??"))?;
            first = false;
            i += 2;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_displays_colon_separated_uppercase() {
        let fp = CaFingerprint("deadbeefcafe".into());
        assert_eq!(fp.to_string(), "DE:AD:BE:EF:CA:FE");
    }
}
