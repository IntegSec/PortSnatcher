//! `RedisPing`: send a RESP `PING`, accept `+PONG` or `-NOAUTH`.

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use ps_core::technique::TechniqueTag;

use super::{Fingerprinter, ProbeContext, ProbeOutcome, Protocol};

const TECHNIQUES: &[TechniqueTag] = &[TechniqueTag::ApiTesting];
const PING: &[u8] = b"*1\r\n$4\r\nPING\r\n";
const READ_LIMIT: usize = 256;

/// Send a Redis RESP `PING`. Any `+PONG\r\n` (anonymous reply) or
/// `-NOAUTH ...` (authentication required) reply is a positive match.
#[derive(Debug, Default)]
pub struct RedisPing;

#[async_trait]
impl Fingerprinter for RedisPing {
    fn name(&self) -> &'static str {
        "redis_ping"
    }

    fn techniques(&self) -> &'static [TechniqueTag] {
        TECHNIQUES
    }

    async fn probe(&self, mut ctx: ProbeContext) -> ProbeOutcome {
        let mut stream = match ctx.stream.take() {
            Some(s) => s,
            None => return ProbeOutcome::Error(anyhow::anyhow!("no stream supplied")),
        };
        if let Err(e) = timeout(ctx.timeout, stream.write_all(PING)).await {
            return ProbeOutcome::Error(anyhow::anyhow!("write timeout: {e}"));
        }
        let mut buf = BytesMut::with_capacity(READ_LIMIT);
        let read = timeout(ctx.timeout, stream.read_buf(&mut buf)).await;
        match read {
            Ok(Ok(0)) => ProbeOutcome::NoMatch,
            Ok(Ok(_)) => {
                let bytes = Bytes::from(buf);
                if bytes.starts_with(b"+PONG") || bytes.starts_with(b"-NOAUTH") {
                    ProbeOutcome::Match {
                        protocol: Protocol::Redis,
                        confidence: 0.95,
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
