//! DumbTunnel end-to-end: fixture echo upstream, client attaches via
//! the allocated loopback port, assert bidirectional flow + the
//! HoldOpenReady / HoldOpenClosed event pair.

use std::sync::Arc;
use std::time::Duration;

use ps_bus::broadcast::BusSender;
use ps_core::event::payload::EventBody;
use ps_core::id::{CatchId, EngagementId};
use ps_proxy::{Ca, DumbTunnel, HoldOpen, HoldOpenManager};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn spawn_echo_upstream() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, handle)
}

fn build_manager() -> (Arc<HoldOpenManager>, TempDir) {
    let tmp = TempDir::new().unwrap();
    let ca = Arc::new(Ca::new_or_load(tmp.path()).unwrap());
    let mgr = Arc::new(HoldOpenManager::new(17100..=17199, ca));
    (mgr, tmp)
}

#[tokio::test]
async fn echoes_bytes_through_tunnel_and_emits_events() {
    let (upstream_addr, _upstream) = spawn_echo_upstream().await;
    let upstream = TcpStream::connect(upstream_addr).await.unwrap();

    let (bus, mut rx) = BusSender::new(64);
    let (mgr, _tmp) = build_manager();

    let tunnel = Box::new(DumbTunnel::new(mgr.clone()));
    let catch_id = CatchId::new();
    let engagement_id = EngagementId::new();

    let ep = tunnel
        .establish(
            catch_id,
            upstream,
            upstream_addr,
            None,
            bus.clone(),
            engagement_id,
        )
        .await
        .unwrap();

    assert!(mgr.port_range.contains(&ep.local_port));

    // HoldOpenReady is emitted before any client attach.
    let ready = rx.recv().await.expect("ready event");
    match &ready.body {
        EventBody::HoldOpenReady(r) => {
            assert_eq!(r.local_port, ep.local_port);
            assert_eq!(r.mode, "dumb_tunnel");
            assert!(r.ca_fingerprint.is_none());
            assert_eq!(r.upstream, upstream_addr.to_string());
        }
        other => panic!("expected HoldOpenReady, got {other:?}"),
    }

    // Client attaches and exchanges bytes.
    let mut client = TcpStream::connect(("127.0.0.1", ep.local_port))
        .await
        .unwrap();
    client.write_all(b"hi").await.unwrap();
    let mut buf = [0u8; 2];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hi");

    // Close the client; the tunnel emits HoldOpenClosed.
    drop(client);

    let closed = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("closed event arrived in time")
        .expect("bus open");
    match &closed.body {
        EventBody::HoldOpenClosed(c) => {
            assert!(
                matches!(c.reason.as_str(), "pentester_detach" | "upstream_closed"),
                "unexpected reason: {}",
                c.reason
            );
        }
        other => panic!("expected HoldOpenClosed, got {other:?}"),
    }
}

#[tokio::test]
async fn idle_timeout_closes_tunnel_when_no_client_attaches() {
    let (upstream_addr, _upstream) = spawn_echo_upstream().await;
    let upstream = TcpStream::connect(upstream_addr).await.unwrap();

    let (bus, mut rx) = BusSender::new(64);
    let (mgr, _tmp) = build_manager();

    // Short idle timeout so the test doesn't wait 5 minutes.
    let tunnel =
        Box::new(DumbTunnel::new(mgr.clone()).with_idle_timeout(Duration::from_millis(200)));
    let catch_id = CatchId::new();
    let engagement_id = EngagementId::new();

    let _ep = tunnel
        .establish(
            catch_id,
            upstream,
            upstream_addr,
            None,
            bus.clone(),
            engagement_id,
        )
        .await
        .unwrap();

    // Drain the ready event.
    let _ = rx.recv().await.unwrap();

    // Don't attach; expect idle_timeout.
    let closed = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("closed event arrived")
        .expect("bus open");
    match &closed.body {
        EventBody::HoldOpenClosed(c) => assert_eq!(c.reason, "idle_timeout"),
        other => panic!("expected HoldOpenClosed, got {other:?}"),
    }
}
