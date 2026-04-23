//! `SshBanner`: passive read with a strict `SSH-` prefix assertion.

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

use ps_core::technique::TechniqueTag;

use super::{Fingerprinter, ProbeContext, ProbeOutcome, Protocol};

const TECHNIQUES: &[TechniqueTag] = &[TechniqueTag::Recon];
const READ_LIMIT: usize = 512;

/// SSH announces itself with `SSH-<protoversion>-<softwareversion>\r\n`
/// as the very first bytes on the wire. This probe reads and asserts
/// that prefix; anything else is `NoMatch`.
#[derive(Debug, Default)]
pub struct SshBanner;

#[async_trait]
impl Fingerprinter for SshBanner {
    fn name(&self) -> &'static str {
        "ssh_banner"
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
            Ok(Ok(_)) => {
                let bytes = Bytes::from(buf);
                if bytes.starts_with(b"SSH-") {
                    let _ = tokio::fs::create_dir_all(&ctx.artifacts_dir).await;
                    let _ =
                        tokio::fs::write(ctx.artifacts_dir.join("ssh-banner.bin"), &bytes).await;
                    ProbeOutcome::Match {
                        protocol: Protocol::Ssh,
                        confidence: 0.9,
                        bytes,
                    }
                } else {
                    ProbeOutcome::NoMatch
                }
            }
            Ok(Err(e)) => ProbeOutcome::Error(anyhow::Error::new(e)),
            Err(_) => ProbeOutcome::NoMatch,
        }
    }
}
