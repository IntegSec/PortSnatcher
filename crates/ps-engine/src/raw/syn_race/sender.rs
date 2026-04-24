//! Raw-socket SYN sender for the Linux SYN race.
//!
//! Opens a `Layer4(IPPROTO_TCP)` raw socket via `pnet::transport`, builds
//! TCP SYN headers via `pnet::packet::tcp`, and hands them to the kernel
//! which fills in the IPv4 header from routing. Requires `CAP_NET_RAW`.

use std::net::Ipv4Addr;

use anyhow::Context;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags};
use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol, TransportSender};

use super::packet::TCP_HEADER_LEN;

pub struct SynSender {
    tx: TransportSender,
    src_ip: Ipv4Addr,
}

impl SynSender {
    /// Open a raw-socket transport channel for sending TCP segments.
    /// `src_ip` is our kernel-routing-chosen local IP; it must match
    /// the IP the kernel actually uses when `sendto()` hits the wire,
    /// otherwise the TCP checksum won't validate and the target drops
    /// our SYN.
    pub fn open(src_ip: Ipv4Addr) -> anyhow::Result<Self> {
        let (tx, _rx) = transport_channel(
            4096,
            TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
        )
        .context("transport_channel(IPPROTO_TCP) — needs CAP_NET_RAW")?;
        Ok(Self { tx, src_ip })
    }

    /// Send a single SYN targeting `(dst_ip, dst_port)` with a
    /// caller-chosen source port and initial sequence number.
    pub fn send_syn(
        &mut self,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        isn: u32,
    ) -> anyhow::Result<()> {
        let mut buf = [0u8; TCP_HEADER_LEN];
        {
            let mut tcp = MutableTcpPacket::new(&mut buf)
                .context("allocate MutableTcpPacket")?;
            tcp.set_source(src_port);
            tcp.set_destination(dst_port);
            tcp.set_sequence(isn);
            tcp.set_acknowledgement(0);
            tcp.set_data_offset(5);
            tcp.set_flags(TcpFlags::SYN);
            tcp.set_window(29200);
            tcp.set_urgent_ptr(0);
            tcp.set_checksum(0);
            let csum = ipv4_checksum(&tcp.to_immutable(), &self.src_ip, &dst_ip);
            tcp.set_checksum(csum);
        }

        // Send. pnet wraps our TCP bytes into an IPv4 datagram via the
        // kernel's raw-socket send path; kernel fills IP header from
        // routing tables (incl. the source IP, which we assume matches
        // `self.src_ip` — this is the standard single-NIC assumption).
        let pkt = MutableTcpPacket::new(&mut buf)
            .context("re-wrap MutableTcpPacket for send")?;
        self.tx
            .send_to(pkt, std::net::IpAddr::V4(dst_ip))
            .context("send_to raw TCP")?;
        Ok(())
    }
}

/// Best-effort discovery of the local IPv4 we'd use to reach `target`.
/// Uses the standard UDP-connect trick: bind an unconnected UDP socket,
/// call `connect()` (which just populates kernel routing state — no
/// packets sent), read back `local_addr()`. Works on every OS we care
/// about; kept here rather than in a shared util because SynRace is the
/// only caller today.
pub fn discover_local_ipv4(target: Ipv4Addr) -> anyhow::Result<Ipv4Addr> {
    use std::net::{SocketAddr, SocketAddrV4, UdpSocket};

    let sock = UdpSocket::bind("0.0.0.0:0").context("bind UDP for local-IP discovery")?;
    sock.connect(SocketAddrV4::new(target, 80))
        .context("connect UDP to probe local routing")?;
    match sock.local_addr()? {
        SocketAddr::V4(v4) => Ok(*v4.ip()),
        SocketAddr::V6(_) => {
            anyhow::bail!("discovered a v6 local for a v4 target — multi-stack host?")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_ipv4_resolves() {
        // Resolving local IP for a public address never sends packets
        // (UDP connect is routing lookup only) so this is safe in CI.
        let got = discover_local_ipv4(Ipv4Addr::new(1, 1, 1, 1));
        // CI runners always have a routable IPv4.
        assert!(got.is_ok(), "could not resolve local IPv4: {got:?}");
    }
}
