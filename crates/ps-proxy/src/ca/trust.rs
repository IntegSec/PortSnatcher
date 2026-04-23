//! Platform trust-store install / uninstall / detect.
//!
//! Each operation shells out to the platform-native tool. None of the
//! three requires a Rust dependency beyond what's already pulled in by
//! `rustls`; none is exercised in CI (CI's trust store is shared across
//! jobs and PortSnatcher is not allowed to mutate it — the check is
//! manual on the operator's own workstation). Errors from the platform
//! tool bubble up verbatim so the operator can paste the message when
//! triaging.

use std::path::Path;
use std::process::Command;

use anyhow::{anyhow, Context};

/// Install the CA certificate at `ca_cert_path` into the current OS's
/// trust store.
///
/// Requires elevation on every platform:
///
/// - **Linux**: copies the cert to
///   `/usr/local/share/ca-certificates/portsnatcher.crt` and runs
///   `update-ca-certificates`.
/// - **macOS**: runs
///   `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain`.
/// - **Windows**: runs PowerShell
///   `Import-Certificate -FilePath <path> -CertStoreLocation Cert:\LocalMachine\Root`.
pub fn install(ca_cert_path: &Path) -> anyhow::Result<()> {
    let cert_str = ca_cert_path.to_string_lossy().into_owned();

    #[cfg(target_os = "linux")]
    {
        let dest = "/usr/local/share/ca-certificates/portsnatcher.crt";
        std::fs::copy(ca_cert_path, dest).with_context(|| format!("copy {cert_str} -> {dest}"))?;
        run_and_check(
            Command::new("update-ca-certificates"),
            "update-ca-certificates",
        )?;
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        let mut cmd = Command::new("security");
        cmd.args([
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
            "/Library/Keychains/System.keychain",
        ]);
        cmd.arg(&cert_str);
        run_and_check(cmd, "security add-trusted-cert")?;
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    {
        let mut cmd = Command::new("powershell");
        cmd.args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!(
                "Import-Certificate -FilePath '{}' -CertStoreLocation Cert:\\LocalMachine\\Root",
                cert_str.replace('\'', "''")
            ),
        ]);
        run_and_check(cmd, "Import-Certificate")?;
        return Ok(());
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = cert_str;
        Err(anyhow!(
            "trust-store install not supported on this platform"
        ))
    }
}

/// Uninstall the PortSnatcher CA from the current OS's trust store.
/// Mirrors [`install`] on each platform.
pub fn uninstall() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let dest = "/usr/local/share/ca-certificates/portsnatcher.crt";
        // Removing the file is idempotent; don't error if it's already gone.
        let _ = std::fs::remove_file(dest);
        run_and_check(
            {
                let mut cmd = Command::new("update-ca-certificates");
                cmd.arg("--fresh");
                cmd
            },
            "update-ca-certificates --fresh",
        )?;
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        let mut cmd = Command::new("security");
        cmd.args([
            "delete-certificate",
            "-c",
            "PortSnatcher CA",
            "/Library/Keychains/System.keychain",
        ]);
        run_and_check(cmd, "security delete-certificate")?;
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    {
        let mut cmd = Command::new("powershell");
        cmd.args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-ChildItem -Path Cert:\\LocalMachine\\Root | Where-Object { $_.Subject -match 'PortSnatcher CA' } | Remove-Item",
        ]);
        run_and_check(cmd, "Remove-Item from Cert:\\LocalMachine\\Root")?;
        return Ok(());
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    Err(anyhow!(
        "trust-store uninstall not supported on this platform"
    ))
}

/// Best-effort detection of whether the PortSnatcher CA is currently
/// trusted.
///
/// Returns `Ok(false)` when the platform probe binary (e.g.
/// `update-ca-certificates` isn't installed, Keychain missing, etc.)
/// is unavailable — those cases are "not installed" for the purposes
/// of the user-facing check. `Err` only surfaces when we got *partial*
/// information and can't commit to a yes/no answer.
pub fn is_installed() -> anyhow::Result<bool> {
    #[cfg(target_os = "linux")]
    {
        let path = "/etc/ssl/certs/ca-certificates.crt";
        if !std::path::Path::new(path).is_file() {
            return Ok(false);
        }
        let bundle = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => return Ok(false),
        };
        // The install writes our subject into the bundle; grep for it.
        Ok(bundle.contains("PortSnatcher CA"))
    }

    #[cfg(target_os = "macos")]
    {
        let output = Command::new("security")
            .args([
                "find-certificate",
                "-c",
                "PortSnatcher CA",
                "/Library/Keychains/System.keychain",
            ])
            .output();
        match output {
            Ok(out) => Ok(out.status.success()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(anyhow!("security find-certificate: {e}")),
        }
    }

    #[cfg(target_os = "windows")]
    {
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "if (Get-ChildItem -Path Cert:\\LocalMachine\\Root | Where-Object { $_.Subject -match 'PortSnatcher CA' }) { Write-Output 'yes' } else { Write-Output 'no' }",
            ])
            .output();
        match output {
            Ok(out) if out.status.success() => {
                let text = String::from_utf8_lossy(&out.stdout);
                Ok(text.trim() == "yes")
            }
            Ok(_) => Ok(false),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(anyhow!("powershell probe: {e}")),
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    Ok(false)
}

#[allow(dead_code)]
fn run_and_check(mut cmd: Command, label: &str) -> anyhow::Result<()> {
    let status = cmd.status().with_context(|| format!("spawn {label}"))?;
    if !status.success() {
        return Err(anyhow!(
            "{label} exited with {status} — trust-store step requires elevation and a working platform toolchain",
        ));
    }
    Ok(())
}
