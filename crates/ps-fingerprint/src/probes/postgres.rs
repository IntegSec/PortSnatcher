//! `PostgresStartup`: send a v3 StartupMessage, accept `R` or `E`.

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use ps_core::technique::TechniqueTag;

use super::{Fingerprinter, ProbeContext, ProbeOutcome, Protocol};

const TECHNIQUES: &[TechniqueTag] = &[TechniqueTag::ApiTesting];
const READ_LIMIT: usize = 1024;

/// Send a v3 StartupMessage for user=postgres. Postgres always replies
/// with either an AuthenticationRequest (`R`) or an ErrorResponse (`E`)
/// — either one is a confident match.
#[derive(Debug, Default)]
pub struct PostgresStartup;

#[async_trait]
impl Fingerprinter for PostgresStartup {
    fn name(&self) -> &'static str {
        "postgres_startup"
    }

    fn techniques(&self) -> &'static [TechniqueTag] {
        TECHNIQUES
    }

    async fn probe(&self, mut ctx: ProbeContext) -> ProbeOutcome {
        let mut stream = match ctx.stream.take() {
            Some(s) => s,
            None => return ProbeOutcome::Error(anyhow::anyhow!("no stream supplied")),
        };

        let packet = build_startup_message();
        if let Err(e) = timeout(ctx.timeout, stream.write_all(&packet)).await {
            return ProbeOutcome::Error(anyhow::anyhow!("write timeout: {e}"));
        }

        let mut buf = BytesMut::with_capacity(READ_LIMIT);
        let read = timeout(ctx.timeout, stream.read_buf(&mut buf)).await;
        match read {
            Ok(Ok(0)) => ProbeOutcome::NoMatch,
            Ok(Ok(_)) => {
                let bytes = Bytes::from(buf);
                match bytes.first() {
                    Some(&b'R') | Some(&b'E') => ProbeOutcome::Match {
                        protocol: Protocol::Postgres,
                        confidence: 0.9,
                        bytes,
                    },
                    _ => ProbeOutcome::NoMatch,
                }
            }
            Ok(Err(e)) => ProbeOutcome::Error(anyhow::Error::new(e)),
            Err(_) => ProbeOutcome::NoMatch,
        }
    }
}

fn build_startup_message() -> Vec<u8> {
    // Layout: [length u32 BE][protocol u32 BE = 0x00030000][user\0postgres\0\0]
    let params: &[u8] = b"user\0postgres\0\0";
    let total_len = 4 /*length*/ + 4 /*protocol*/ + params.len();
    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&(total_len as u32).to_be_bytes());
    out.extend_from_slice(&0x0003_0000u32.to_be_bytes());
    out.extend_from_slice(params);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_length_prefix_is_self_consistent() {
        let p = build_startup_message();
        let declared = u32::from_be_bytes([p[0], p[1], p[2], p[3]]) as usize;
        assert_eq!(declared, p.len());
        // Protocol major=3, minor=0.
        let proto = u32::from_be_bytes([p[4], p[5], p[6], p[7]]);
        assert_eq!(proto, 0x0003_0000);
    }
}
