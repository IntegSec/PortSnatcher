//! CA generation, load, and leaf issuance via `rcgen`.
//!
//! The CA is ECDSA P-256 with a 10-year lifetime; leaves are ECDSA
//! P-256 with a 90-day lifetime. The algorithm choice is justified in
//! the Phase 3 plan notes — faster than RSA-3072 on pentester laptops,
//! accepted unmodified by every platform trust store we target, and
//! pairs cleanly with rustls's TLS 1.3 defaults.

use std::fs;
use std::io::Cursor;
use std::path::Path;

use anyhow::{anyhow, Context};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose, SanType, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

use super::storage::{cert_path, fingerprint_path, key_path};

/// Raw on-disk bundle: DER cert, PEM key, hex fingerprint.
pub(super) struct CaBundle {
    pub cert_der: Vec<u8>,
    pub key_pem: String,
    pub fingerprint_sha256: String,
}

/// Generate or load the CA at `dir`. Idempotent.
pub(super) fn generate_or_load(dir: &Path) -> anyhow::Result<CaBundle> {
    fs::create_dir_all(dir).with_context(|| format!("create CA dir {}", dir.display()))?;

    let cert_file = cert_path(dir);
    let key_file = key_path(dir);
    let fp_file = fingerprint_path(dir);

    if cert_file.is_file() && key_file.is_file() {
        let cert_pem = fs::read_to_string(&cert_file)
            .with_context(|| format!("read {}", cert_file.display()))?;
        let key_pem = fs::read_to_string(&key_file)
            .with_context(|| format!("read {}", key_file.display()))?;
        let cert_der =
            first_cert_der(&cert_pem).context("CA cert PEM missing CERTIFICATE block")?;
        let fingerprint_sha256 = fingerprint_hex(&cert_der);
        // Write through the fingerprint if missing; don't fail if we can't.
        let _ = fs::write(&fp_file, format!("{fingerprint_sha256}\n"));
        return Ok(CaBundle {
            cert_der,
            key_pem,
            fingerprint_sha256,
        });
    }

    let (cert_pem, cert_der, key_pem) = generate_ca()?;
    fs::write(&cert_file, &cert_pem).with_context(|| format!("write {}", cert_file.display()))?;
    fs::write(&key_file, &key_pem).with_context(|| format!("write {}", key_file.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&key_file)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&key_file, perms)?;
    }

    let fingerprint_sha256 = fingerprint_hex(&cert_der);
    fs::write(&fp_file, format!("{fingerprint_sha256}\n"))
        .with_context(|| format!("write {}", fp_file.display()))?;

    Ok(CaBundle {
        cert_der,
        key_pem,
        fingerprint_sha256,
    })
}

/// Generate a fresh ECDSA P-256 self-signed CA.
///
/// Returns `(cert_pem, cert_der, key_pem)`. Exposed for callers (e.g.
/// tests, tools) that want a CA bundle without touching the disk.
pub fn generate_ca() -> anyhow::Result<(String, Vec<u8>, String)> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "PortSnatcher CA");
    dn.push(DnType::OrganizationName, "IntegSec PortSnatcher");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::hours(1);
    params.not_after = now + Duration::days(365 * 10);

    let cert = params.self_signed(&key)?;
    let cert_pem = cert.pem();
    let cert_der = cert.der().to_vec();
    let key_pem = key.serialize_pem();

    Ok((cert_pem, cert_der, key_pem))
}

/// Sign a leaf certificate for `hostname` using the CA in
/// `(ca_cert_der, ca_key_pem)`. Returns a rustls `CertifiedKey` whose
/// chain is `[leaf, ca]` as rustls expects.
pub fn sign_leaf_internal(
    ca_cert_der: &[u8],
    ca_key_pem: &str,
    hostname: &str,
) -> anyhow::Result<CertifiedKey> {
    // Reconstruct an in-memory CA Certificate. `self_signed` produces a
    // cert with a different serial/timestamps than the on-disk original,
    // but since the subject DN and public key match, any leaf we sign
    // with it chains identically against the stored-on-disk CA.
    let ca_cert_pem = der_to_pem(ca_cert_der, "CERTIFICATE");
    let ca_params = CertificateParams::from_ca_cert_pem(&ca_cert_pem)
        .context("parse CA cert PEM for issuer")?;
    let ca_key = KeyPair::from_pem(ca_key_pem).context("parse CA key PEM")?;
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .context("reconstitute in-memory CA certificate")?;

    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut leaf_params = CertificateParams::new(vec![hostname.to_string()])?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, hostname);
    leaf_params.distinguished_name = dn;
    leaf_params.subject_alt_names = vec![SanType::DnsName(
        hostname
            .to_string()
            .try_into()
            .map_err(|e| anyhow!("bad hostname {hostname:?}: {e}"))?,
    )];
    let now = OffsetDateTime::now_utc();
    leaf_params.not_before = now - Duration::hours(1);
    leaf_params.not_after = now + Duration::days(90);

    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key)?;
    let leaf_der = leaf_cert.der().to_vec();

    // Extract the PKCS#8 DER of the leaf key from rcgen's PEM.
    let leaf_key_pem = leaf_key.serialize_pem();
    let leaf_key_der =
        first_pkcs8_der(&leaf_key_pem).context("leaf key PEM missing PRIVATE KEY block")?;

    let pkcs8 = PrivatePkcs8KeyDer::from(leaf_key_der);
    let signing_key = rustls::crypto::ring::sign::any_ecdsa_type(&pkcs8.into())
        .map_err(|e| anyhow!("any_ecdsa_type: {e:?}"))?;

    let chain = vec![
        CertificateDer::from(leaf_der),
        CertificateDer::from(ca_cert_der.to_vec()),
    ];
    Ok(CertifiedKey::new(chain, signing_key))
}

/// SHA-256 of `der`, hex-encoded lowercase.
fn fingerprint_hex(der: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(der);
    hex::encode(h.finalize())
}

/// Return the DER of the first `CERTIFICATE` block in `pem`.
fn first_cert_der(pem: &str) -> anyhow::Result<Vec<u8>> {
    let mut reader = Cursor::new(pem.as_bytes());
    for item in rustls_pemfile::certs(&mut reader) {
        let der = item.context("read CERTIFICATE block")?;
        return Ok(der.as_ref().to_vec());
    }
    Err(anyhow!("no CERTIFICATE block"))
}

/// Return the DER of the first `PRIVATE KEY` (PKCS#8) block in `pem`.
fn first_pkcs8_der(pem: &str) -> anyhow::Result<Vec<u8>> {
    let mut reader = Cursor::new(pem.as_bytes());
    for item in rustls_pemfile::pkcs8_private_keys(&mut reader) {
        let der = item.context("read PRIVATE KEY block")?;
        return Ok(der.secret_pkcs8_der().to_vec());
    }
    Err(anyhow!("no PRIVATE KEY block"))
}

/// Wrap raw `der` bytes into a PEM block with the given tag.
fn der_to_pem(der: &[u8], tag: &str) -> String {
    // Minimal base64 via a no-extra-crate helper so we don't need to
    // pull `base64` in as a direct dependency.
    let b64 = base64_encode(der);
    let mut out = String::with_capacity(b64.len() + 64);
    out.push_str(&format!("-----BEGIN {tag}-----\n"));
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {tag}-----\n"));
    out
}

/// Tiny RFC 4648 base64 encoder (stdlib-free). Private because we
/// only use it for round-tripping DER -> PEM internally.
fn base64_encode(input: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(((input.len() + 2) / 3) * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let b0 = input[i];
        let b1 = input[i + 1];
        let b2 = input[i + 2];
        out.push(ALPHA[(b0 >> 2) as usize] as char);
        out.push(ALPHA[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(ALPHA[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        out.push(ALPHA[(b2 & 0x3f) as usize] as char);
        i += 3;
    }
    let remaining = input.len() - i;
    if remaining == 1 {
        let b0 = input[i];
        out.push(ALPHA[(b0 >> 2) as usize] as char);
        out.push(ALPHA[((b0 & 0x03) << 4) as usize] as char);
        out.push('=');
        out.push('=');
    } else if remaining == 2 {
        let b0 = input[i];
        let b1 = input[i + 1];
        out.push(ALPHA[(b0 >> 2) as usize] as char);
        out.push(ALPHA[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(ALPHA[((b1 & 0x0f) << 2) as usize] as char);
        out.push('=');
    }
    out
}
