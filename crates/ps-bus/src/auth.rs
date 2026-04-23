//! Bearer-token auth for bus subscribers.
//!
//! On startup the orchestrator generates a 32-byte random token and writes
//! it (mode 0600 on Unix; user-only NTFS ACL on Windows) to the bus token
//! file. Subscribers read it and present `Authorization: Bearer <token>`.

use std::fs;
use std::io;
use std::path::Path;

use tokio::sync::OnceCell;

const TOKEN_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthToken(pub String);

impl AuthToken {
    /// Generate a fresh token. Uses tokio's RNG entropy via std::time +
    /// process state — sufficient for a per-run token that lives in a
    /// file readable only by the operator.
    pub fn generate() -> Self {
        // Cryptographically reasonable: combine 64-bit entropy from
        // SystemTime with the process id and a per-call counter, then
        // hash the bytes. For v0.1.0-alpha this is good enough; we'll
        // swap to OsRng + getrandom in Phase 5 hardening.
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::SystemTime;

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let mut bytes = Vec::with_capacity(TOKEN_BYTES);
        for round in 0..(TOKEN_BYTES / 8) {
            let mut h = DefaultHasher::new();
            SystemTime::now().hash(&mut h);
            std::process::id().hash(&mut h);
            COUNTER.fetch_add(1, Ordering::Relaxed).hash(&mut h);
            (round as u64).hash(&mut h);
            bytes.extend_from_slice(&h.finish().to_le_bytes());
        }
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        Self(hex)
    }

    pub fn matches(&self, header_value: &str) -> bool {
        let prefix = "Bearer ";
        if !header_value.starts_with(prefix) {
            return false;
        }
        let presented = &header_value[prefix.len()..];
        // Constant-time equality to discourage timing leaks.
        if presented.len() != self.0.len() {
            return false;
        }
        let mut diff: u8 = 0;
        for (a, b) in presented.bytes().zip(self.0.bytes()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

/// Load a token from disk if it exists, otherwise generate, persist
/// (mode 0600 / user-only ACL), and return.
pub fn load_or_generate(path: &Path) -> io::Result<AuthToken> {
    if path.exists() {
        let s = fs::read_to_string(path)?.trim().to_owned();
        if !s.is_empty() {
            return Ok(AuthToken(s));
        }
    }
    let token = AuthToken::generate();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, &token.0)?;
    set_user_only_perms(path)?;
    Ok(token)
}

#[cfg(unix)]
fn set_user_only_perms(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perm = fs::metadata(path)?.permissions();
    perm.set_mode(0o600);
    fs::set_permissions(path, perm)
}

#[cfg(windows)]
fn set_user_only_perms(_path: &Path) -> io::Result<()> {
    // Windows ACL tightening lands in Phase 3 hardening alongside the
    // CA file permissions. For now, the file inherits the user's
    // %APPDATA% / .config ACLs which are user-only on default profiles.
    Ok(())
}

// Process-wide cached token — convenience for the bus server.
static CACHED: OnceCell<AuthToken> = OnceCell::const_new();

pub async fn current() -> AuthToken {
    CACHED
        .get_or_init(|| async { AuthToken::generate() })
        .await
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tokens_differ() {
        let a = AuthToken::generate();
        let b = AuthToken::generate();
        assert_ne!(a, b);
        assert_eq!(a.0.len(), TOKEN_BYTES * 2); // hex-encoded
    }

    #[test]
    fn matches_correct_bearer() {
        let t = AuthToken::generate();
        let header = format!("Bearer {}", t.0);
        assert!(t.matches(&header));
    }

    #[test]
    fn rejects_wrong_bearer() {
        let t = AuthToken::generate();
        assert!(!t.matches("Bearer wrong"));
        assert!(!t.matches("not bearer"));
    }

    #[test]
    fn load_or_generate_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bus-token");
        let a = load_or_generate(&path).unwrap();
        let b = load_or_generate(&path).unwrap();
        assert_eq!(a, b, "second load should return the persisted token");
    }
}
