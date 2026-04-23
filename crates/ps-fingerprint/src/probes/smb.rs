//! `SmbNegotiate`: send a NetBIOS session service + SMB1 NEGOTIATE.
//!
//! The SMB1 NEGOTIATE request is used for maximum reachability: any
//! SMB-compliant server (including SMB2/SMB3 servers) will respond,
//! SMB2 servers by upgrading the response into an SMB2 NEGOTIATE reply.

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use ps_core::technique::TechniqueTag;

use super::{Fingerprinter, ProbeContext, ProbeOutcome, Protocol};

const TECHNIQUES: &[TechniqueTag] = &[TechniqueTag::Recon];
const READ_LIMIT: usize = 1024;

/// Minimal SMB1 NEGOTIATE request. NetBIOS session service header is
/// prepended (`\x00` session-message type + 3-byte length), followed by
/// an SMB1 header and a single dialect string `"NT LM 0.12"`.
const NEGOTIATE: &[u8] = b"\x00\x00\x00\x2f\xffSMB\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x0c\x00\x02NT LM 0.12\x00";

/// Send an SMB1 NEGOTIATE and treat any reply as a match.
#[derive(Debug, Default)]
pub struct SmbNegotiate;

#[async_trait]
impl Fingerprinter for SmbNegotiate {
    fn name(&self) -> &'static str {
        "smb_negotiate"
    }

    fn techniques(&self) -> &'static [TechniqueTag] {
        TECHNIQUES
    }

    async fn probe(&self, mut ctx: ProbeContext) -> ProbeOutcome {
        let mut stream = match ctx.stream.take() {
            Some(s) => s,
            None => return ProbeOutcome::Error(anyhow::anyhow!("no stream supplied")),
        };
        if let Err(e) = timeout(ctx.timeout, stream.write_all(NEGOTIATE)).await {
            return ProbeOutcome::Error(anyhow::anyhow!("write timeout: {e}"));
        }
        let mut buf = BytesMut::with_capacity(READ_LIMIT);
        let read = timeout(ctx.timeout, stream.read_buf(&mut buf)).await;
        match read {
            Ok(Ok(0)) => ProbeOutcome::NoMatch,
            Ok(Ok(_)) => {
                let bytes = Bytes::from(buf);
                ProbeOutcome::Match {
                    protocol: Protocol::Smb,
                    confidence: 0.9,
                    bytes,
                }
            }
            Ok(Err(e)) => ProbeOutcome::Error(anyhow::Error::new(e)),
            Err(_) => ProbeOutcome::NoMatch,
        }
    }
}
