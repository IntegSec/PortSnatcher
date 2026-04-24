//! pcap-style SYN-ACK receiver for the Linux SYN race.
//!
//! Opens a `pnet::datalink` channel on a chosen network interface and
//! loops reading layer-2 frames. For each inbound TCP segment with
//! SYN+ACK flags, destination port inside our source-port pool, and
//! source IP in our target set, we emit a [`SynAckHit`] to the caller's
//! Tokio `UnboundedSender`.
//!
//! The receive loop runs on a plain `std::thread` — `pnet::datalink`'s
//! `DataLinkReceiver::next` is blocking sync and mixes poorly with the
//! Tokio runtime. The thread exits when the shutdown flag is set OR
//! when the sender disconnects (channel closed).

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Context;
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::Packet as _;
use tokio::sync::mpsc::UnboundedSender;

/// One SYN-ACK we've detected on the wire.
#[derive(Debug, Clone)]
pub struct SynAckHit {
    pub target_ip: Ipv4Addr,
    pub target_port: u16,
    pub our_src_port: u16,
}

/// Receiver configuration.
pub struct RecvConfig {
    /// Interface to bind to. Must have a usable MAC.
    pub interface: NetworkInterface,
    /// Set of target IPs we're currently racing; SYN-ACKs from other
    /// sources are ignored. Passed as a snapshot so the receiver loop
    /// doesn't have to hold a lock.
    pub targets: Arc<HashSet<Ipv4Addr>>,
    /// Source-port pool bounds `(low, high)` inclusive. Only SYN-ACKs
    /// whose destination port is inside this range are considered ours.
    pub port_pool_bounds: (u16, u16),
    /// Signal the receiver thread to exit. Checked between each packet.
    pub shutdown: Arc<AtomicBool>,
}

/// Spawn the pcap-style receive loop on a background thread.
///
/// Returns the thread handle so callers can `.join()` at shutdown.
/// Errors surface if the datalink channel can't be opened (missing
/// CAP_NET_RAW, interface gone, etc).
pub fn spawn(
    cfg: RecvConfig,
    out: UnboundedSender<SynAckHit>,
) -> anyhow::Result<std::thread::JoinHandle<()>> {
    let (_tx, mut rx) = match datalink::channel(&cfg.interface, Default::default())
        .context("pnet datalink channel — needs CAP_NET_RAW or CAP_NET_ADMIN")?
    {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => anyhow::bail!("unsupported datalink channel type (only Ethernet is supported)"),
    };

    let handle = std::thread::Builder::new()
        .name("portsnatcher-syn-race-recv".into())
        .spawn(move || {
            tracing::debug!(
                iface = %cfg.interface.name,
                "syn-race receiver thread started"
            );
            while !cfg.shutdown.load(Ordering::Relaxed) {
                let pkt = match rx.next() {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!("pnet rx.next error: {e:#}");
                        continue;
                    }
                };
                if let Some(hit) = parse_syn_ack(pkt, &cfg.targets, cfg.port_pool_bounds) {
                    if out.send(hit).is_err() {
                        // Downstream closed; stop.
                        break;
                    }
                }
            }
            tracing::debug!("syn-race receiver thread exiting");
        })
        .context("spawn pnet receiver thread")?;

    Ok(handle)
}

/// Parse a raw Ethernet frame and return a [`SynAckHit`] if the frame
/// is a TCP SYN-ACK from a target we care about into one of our
/// race-pool source ports.
///
/// Public so the unit tests can exercise the filter logic with crafted
/// byte slices (no network stack required).
pub fn parse_syn_ack(
    frame: &[u8],
    targets: &HashSet<Ipv4Addr>,
    port_bounds: (u16, u16),
) -> Option<SynAckHit> {
    let eth = EthernetPacket::new(frame)?;
    if eth.get_ethertype() != EtherTypes::Ipv4 {
        return None;
    }
    let ipv4 = Ipv4Packet::new(eth.payload())?;
    if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return None;
    }
    let src_ip = ipv4.get_source();
    if !targets.contains(&src_ip) {
        return None;
    }
    let tcp = TcpPacket::new(ipv4.payload())?;
    let flags = tcp.get_flags();
    if flags & (TcpFlags::SYN | TcpFlags::ACK) != (TcpFlags::SYN | TcpFlags::ACK) {
        return None;
    }
    let dst_port = tcp.get_destination();
    if dst_port < port_bounds.0 || dst_port > port_bounds.1 {
        return None;
    }
    Some(SynAckHit {
        target_ip: src_ip,
        target_port: tcp.get_source(),
        our_src_port: dst_port,
    })
}

/// Pick the first non-loopback interface with an IPv4 address. Returns
/// `None` on hosts without such an interface (e.g. pure IPv6 or
/// network-namespaced CI runners).
pub fn default_interface() -> Option<NetworkInterface> {
    datalink::interfaces().into_iter().find(|i| {
        !i.is_loopback() && i.is_up() && i.ips.iter().any(|n| matches!(n.ip(), IpAddr::V4(_)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_frame_with_syn_ack(src_ip: Ipv4Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
        use pnet::packet::ethernet::MutableEthernetPacket;
        use pnet::packet::ipv4::MutableIpv4Packet;
        use pnet::packet::tcp::MutableTcpPacket;
        use pnet::util::MacAddr;

        const ETH: usize = 14;
        const IP: usize = 20;
        const TCP: usize = 20;
        let mut buf = vec![0u8; ETH + IP + TCP];

        {
            let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
            eth.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
            eth.set_source(MacAddr(0, 0, 0, 0, 0, 0));
            eth.set_ethertype(EtherTypes::Ipv4);
        }
        {
            let mut ipv4 = MutableIpv4Packet::new(&mut buf[ETH..]).unwrap();
            ipv4.set_version(4);
            ipv4.set_header_length(5);
            ipv4.set_total_length((IP + TCP) as u16);
            ipv4.set_ttl(64);
            ipv4.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ipv4.set_source(src_ip);
            ipv4.set_destination(Ipv4Addr::new(127, 0, 0, 1));
        }
        {
            let mut tcp = MutableTcpPacket::new(&mut buf[ETH + IP..]).unwrap();
            tcp.set_source(src_port);
            tcp.set_destination(dst_port);
            tcp.set_data_offset(5);
            tcp.set_flags(TcpFlags::SYN | TcpFlags::ACK);
            tcp.set_window(29200);
        }
        buf
    }

    #[test]
    fn identifies_syn_ack_from_target() {
        let target = Ipv4Addr::new(192, 0, 2, 10);
        let mut targets = HashSet::new();
        targets.insert(target);
        let frame = build_frame_with_syn_ack(target, 443, 40_500);
        let hit = parse_syn_ack(&frame, &targets, (40_000, 49_999));
        assert!(hit.is_some(), "should recognise SYN-ACK from target");
        let hit = hit.unwrap();
        assert_eq!(hit.target_ip, target);
        assert_eq!(hit.target_port, 443);
        assert_eq!(hit.our_src_port, 40_500);
    }

    #[test]
    fn ignores_non_target_source() {
        let target = Ipv4Addr::new(192, 0, 2, 10);
        let other = Ipv4Addr::new(192, 0, 2, 99);
        let mut targets = HashSet::new();
        targets.insert(target);
        let frame = build_frame_with_syn_ack(other, 443, 40_500);
        assert!(parse_syn_ack(&frame, &targets, (40_000, 49_999)).is_none());
    }

    #[test]
    fn ignores_port_outside_pool() {
        let target = Ipv4Addr::new(192, 0, 2, 10);
        let mut targets = HashSet::new();
        targets.insert(target);
        let frame = build_frame_with_syn_ack(target, 443, 22);
        assert!(parse_syn_ack(&frame, &targets, (40_000, 49_999)).is_none());
    }
}
