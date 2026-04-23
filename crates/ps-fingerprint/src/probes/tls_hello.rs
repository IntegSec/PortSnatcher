//! `TlsHello`: complete a TLS handshake and record ALPN + leaf cert.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::ClientConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use ps_core::technique::TechniqueTag;

use super::{Fingerprinter, ProbeContext, ProbeOutcome, Protocol};

const TECHNIQUES: &[TechniqueTag] = &[TechniqueTag::Recon, TechniqueTag::SslTls];

/// Perform a TLS handshake against the supplied stream with an
/// intentionally permissive cert verifier: we're fingerprinting, not
/// establishing a secure channel. The captured ALPN and server leaf
/// certificate are what matter here.
#[derive(Debug, Default)]
pub struct TlsHello;

#[async_trait]
impl Fingerprinter for TlsHello {
    fn name(&self) -> &'static str {
        "tls_hello"
    }

    fn techniques(&self) -> &'static [TechniqueTag] {
        TECHNIQUES
    }

    async fn probe(&self, mut ctx: ProbeContext) -> ProbeOutcome {
        let stream = match ctx.stream.take() {
            Some(s) => s,
            None => return ProbeOutcome::Error(anyhow::anyhow!("no stream")),
        };

        // Install the default crypto provider on first use. Idempotent.
        let provider = CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));
        let cfg = match ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
        {
            Ok(b) => b
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
                .with_no_client_auth(),
            Err(e) => return ProbeOutcome::Error(anyhow::Error::msg(e.to_string())),
        };
        let connector = TlsConnector::from(Arc::new(cfg));
        // IP-typed ServerName is always well-formed for an IpAddr; no
        // DNS name validation required. `std::net::IpAddr` converts
        // into `rustls_pki_types::IpAddr` via its `From` impl.
        let server_name: ServerName<'static> = ServerName::IpAddress(ctx.target.ip.into());

        let handshake = timeout(ctx.timeout, connector.connect(server_name, stream)).await;
        match handshake {
            Ok(Ok(mut tls)) => {
                let (peer_certs_vec, alpn) = {
                    let (_io, conn) = tls.get_ref();
                    let certs = conn
                        .peer_certificates()
                        .map(|c| c.iter().map(|c| c.to_vec()).collect::<Vec<_>>())
                        .unwrap_or_default();
                    let alpn = conn
                        .alpn_protocol()
                        .map(|b| String::from_utf8_lossy(b).into_owned());
                    (certs, alpn)
                };

                // Best-effort clean shutdown. We still record the match
                // even if the server hangs up without a close_notify.
                let _ = tls.shutdown().await;

                let _ = tokio::fs::create_dir_all(&ctx.artifacts_dir).await;
                if let Some(cert) = peer_certs_vec.first() {
                    let pem = pem::encode(&pem::Pem::new("CERTIFICATE", cert.clone()));
                    let _ = tokio::fs::write(
                        ctx.artifacts_dir.join("tls-servercert.pem"),
                        pem.as_bytes(),
                    )
                    .await;
                }

                let banner = Bytes::from(
                    format!("TLS ALPN: {}", alpn.as_deref().unwrap_or("")).into_bytes(),
                );
                ProbeOutcome::Match {
                    protocol: Protocol::Tls,
                    confidence: 0.95,
                    bytes: banner,
                }
            }
            Ok(Err(_)) | Err(_) => ProbeOutcome::NoMatch,
        }
    }
}

/// No-op server certificate verifier. We are fingerprinting, not
/// establishing trust — accept whatever the server presents so we can
/// still observe ALPN and the leaf cert for probes downstream.
#[derive(Debug)]
struct InsecureVerifier;

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}
