//! XDG-aware paths for the on-disk CA.
//!
//! File layout under `<dir>`:
//!
//! ```text
//! <dir>/
//!   ca.crt                  PEM-encoded CA certificate
//!   ca.key                  PEM-encoded CA private key (chmod 0600 on Unix)
//!   ca-fingerprint.sha256   SHA-256(cert DER), hex, 64 chars + '\n'
//! ```

use std::path::{Path, PathBuf};

use directories::ProjectDirs;

/// Filename for the PEM-encoded CA certificate.
pub const CERT_FILENAME: &str = "ca.crt";
/// Filename for the PEM-encoded CA private key.
pub const KEY_FILENAME: &str = "ca.key";
/// Filename for the hex SHA-256 of the cert DER.
pub const FINGERPRINT_FILENAME: &str = "ca-fingerprint.sha256";

/// Full path to the CA certificate under `dir`.
pub fn cert_path(dir: &Path) -> PathBuf {
    dir.join(CERT_FILENAME)
}

/// Full path to the CA private key under `dir`.
pub fn key_path(dir: &Path) -> PathBuf {
    dir.join(KEY_FILENAME)
}

/// Full path to the fingerprint file under `dir`.
pub fn fingerprint_path(dir: &Path) -> PathBuf {
    dir.join(FINGERPRINT_FILENAME)
}

/// Resolve the default CA directory per the target platform.
///
/// - Linux:   `$XDG_CONFIG_HOME/portsnatcher/ca` (falls back to `~/.config/...`)
/// - macOS:   `~/Library/Application Support/com.integsec.portsnatcher/ca`
/// - Windows: `%APPDATA%\integsec\portsnatcher\config\ca`
///
/// Returns `None` when no home directory is available (headless service
/// accounts, CI runners with a stripped HOME, etc.). Callers should
/// fall back to an explicit `--ca-dir` in that case.
pub fn default_dir() -> Option<PathBuf> {
    ProjectDirs::from("com", "integsec", "portsnatcher").map(|dirs| dirs.config_dir().join("ca"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn path_helpers_compose_filenames() {
        let root = Path::new("/tmp/x");
        assert_eq!(cert_path(root), Path::new("/tmp/x/ca.crt"));
        assert_eq!(key_path(root), Path::new("/tmp/x/ca.key"));
        assert_eq!(
            fingerprint_path(root),
            Path::new("/tmp/x/ca-fingerprint.sha256")
        );
    }
}
