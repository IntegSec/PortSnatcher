//! Single-attempt TCP connect worker.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use ps_core::target::Target;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Result of one connect attempt.
pub enum AttemptOutcome {
    Caught {
        stream: TcpStream,
        detect_latency: Duration,
    },
    Closed,
    Transient,
}

pub async fn attempt(target: Target, connect_timeout: Duration) -> AttemptOutcome {
    let addr = SocketAddr::new(target.ip, target.port);
    let start = Instant::now();
    match timeout(connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => AttemptOutcome::Caught {
            stream,
            detect_latency: start.elapsed(),
        },
        Ok(Err(e)) if matches!(e.kind(), std::io::ErrorKind::ConnectionRefused) => {
            AttemptOutcome::Closed
        }
        _ => AttemptOutcome::Transient,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn catches_open_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let target = Target::new("127.0.0.1".parse().unwrap(), port);
        match attempt(target, Duration::from_millis(500)).await {
            AttemptOutcome::Caught { .. } => {}
            _ => panic!("expected Caught"),
        }
    }

    #[tokio::test]
    async fn classifies_closed_port() {
        let target = Target::new("127.0.0.1".parse().unwrap(), 1);
        match attempt(target, Duration::from_millis(200)).await {
            AttemptOutcome::Closed | AttemptOutcome::Transient => {}
            _ => panic!("expected Closed or Transient"),
        }
    }
}
