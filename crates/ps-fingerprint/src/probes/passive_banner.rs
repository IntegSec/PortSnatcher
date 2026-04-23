//! `PassiveBanner`: wait for the server to speak first, classify what it says.

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

use ps_core::technique::TechniqueTag;

use super::{Fingerprinter, ProbeContext, ProbeOutcome, Protocol};

const TECHNIQUES: &[TechniqueTag] = &[TechniqueTag::Recon];
const READ_LIMIT: usize = 4096;

/// Read up to 4 KiB from the server and classify based on the prefix.
///
/// Recognises `SSH-` (→ Ssh) and `HTTP/` (→ Http11). Anything else is
/// `Protocol::Unknown` with low confidence so more targeted probes get
/// a chance to speak.
#[derive(Debug, Default)]
pub struct PassiveBanner;

#[async_trait]
impl Fingerprinter for PassiveBanner {
    fn name(&self) -> &'static str {
        "passive_banner"
    }

    fn techniques(&self) -> &'static [TechniqueTag] {
        TECHNIQUES
    }

    async fn probe(&self, mut ctx: ProbeContext) -> ProbeOutcome {
        let mut stream = match ctx.stream.take() {
            Some(s) => s,
            None => return ProbeOutcome::Error(anyhow::anyhow!("no stream supplied")),
        };
        let mut buf = BytesMut::with_capacity(READ_LIMIT);
        let read = timeout(ctx.timeout, stream.read_buf(&mut buf)).await;
        match read {
            Ok(Ok(0)) => ProbeOutcome::NoMatch,
            Ok(Ok(_n)) => {
                let bytes = Bytes::from(buf);
                // Best-effort artifact write.
                let _ = tokio::fs::create_dir_all(&ctx.artifacts_dir).await;
                let path = ctx.artifacts_dir.join("banner.bin");
                let _ = tokio::fs::write(&path, &bytes).await;

                let protocol = classify(&bytes);
                let confidence = if matches!(protocol, Protocol::Unknown) {
                    0.2
                } else {
                    0.85
                };
                ProbeOutcome::Match {
                    protocol,
                    confidence,
                    bytes,
                }
            }
            Ok(Err(e)) => ProbeOutcome::Error(anyhow::Error::new(e)),
            Err(_) => ProbeOutcome::NoMatch,
        }
    }
}

fn classify(bytes: &[u8]) -> Protocol {
    if bytes.starts_with(b"SSH-") {
        return Protocol::Ssh;
    }
    if bytes.starts_with(b"HTTP/") {
        return Protocol::Http11;
    }
    Protocol::Unknown
}
