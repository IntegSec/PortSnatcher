//! HTTP/1.1 probes: `HttpHead` and `HttpGetRoot`.
//!
//! Both send a minimal HTTP/1.1 request, read the response with a small
//! timeout, validate the status line with `httparse`, and persist the
//! raw bytes under `<artifacts_dir>/http/<method>.response`.

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use ps_core::technique::TechniqueTag;

use super::{Fingerprinter, ProbeContext, ProbeOutcome, Protocol};

const HEAD_TECHNIQUES: &[TechniqueTag] = &[TechniqueTag::Recon, TechniqueTag::WebApp];
const GET_TECHNIQUES: &[TechniqueTag] = &[TechniqueTag::WebApp];
const READ_LIMIT: usize = 16 * 1024;

/// Sends `HEAD / HTTP/1.1` and matches any syntactically-valid response.
#[derive(Debug, Default)]
pub struct HttpHead;

/// Sends `GET / HTTP/1.1` and matches any syntactically-valid response.
#[derive(Debug, Default)]
pub struct HttpGetRoot;

#[async_trait]
impl Fingerprinter for HttpHead {
    fn name(&self) -> &'static str {
        "http_head"
    }

    fn techniques(&self) -> &'static [TechniqueTag] {
        HEAD_TECHNIQUES
    }

    async fn probe(&self, ctx: ProbeContext) -> ProbeOutcome {
        run_http(ctx, "HEAD", "head.response").await
    }
}

#[async_trait]
impl Fingerprinter for HttpGetRoot {
    fn name(&self) -> &'static str {
        "http_get_root"
    }

    fn techniques(&self) -> &'static [TechniqueTag] {
        GET_TECHNIQUES
    }

    async fn probe(&self, ctx: ProbeContext) -> ProbeOutcome {
        run_http(ctx, "GET", "get.response").await
    }
}

async fn run_http(
    mut ctx: ProbeContext,
    method: &'static str,
    artifact_name: &'static str,
) -> ProbeOutcome {
    let mut stream = match ctx.stream.take() {
        Some(s) => s,
        None => return ProbeOutcome::Error(anyhow::anyhow!("no stream supplied")),
    };

    let request = format!(
        "{method} / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: portsnatcher/{ver}\r\nConnection: close\r\n\r\n",
        method = method,
        host = ctx.target.ip,
        ver = crate::VERSION,
    );

    if let Err(e) = timeout(ctx.timeout, stream.write_all(request.as_bytes())).await {
        return ProbeOutcome::Error(anyhow::anyhow!("write timeout: {e}"));
    }

    let mut buf = BytesMut::with_capacity(READ_LIMIT);
    let read = timeout(ctx.timeout, async {
        // Read until EOF or READ_LIMIT, whichever comes first.
        while buf.len() < READ_LIMIT {
            let n = stream.read_buf(&mut buf).await?;
            if n == 0 {
                break;
            }
        }
        Ok::<_, std::io::Error>(())
    })
    .await;

    match read {
        Ok(Ok(())) if !buf.is_empty() => {
            let bytes = Bytes::from(buf);

            // Persist the raw response for analysts.
            let dir = ctx.artifacts_dir.join("http");
            let _ = tokio::fs::create_dir_all(&dir).await;
            let _ = tokio::fs::write(dir.join(artifact_name), &bytes).await;

            // Validate by parsing the status line with httparse.
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut resp = httparse::Response::new(&mut headers);
            match resp.parse(&bytes) {
                Ok(_) if resp.code.is_some() => ProbeOutcome::Match {
                    protocol: Protocol::Http11,
                    confidence: 0.9,
                    bytes,
                },
                _ => {
                    // Fallback: accept anything that looks like a status line.
                    if bytes.starts_with(b"HTTP/") {
                        ProbeOutcome::Match {
                            protocol: Protocol::Http11,
                            confidence: 0.9,
                            bytes,
                        }
                    } else {
                        ProbeOutcome::NoMatch
                    }
                }
            }
        }
        Ok(Ok(())) => ProbeOutcome::NoMatch,
        Ok(Err(e)) => ProbeOutcome::Error(anyhow::Error::new(e)),
        Err(_) => ProbeOutcome::NoMatch,
    }
}
