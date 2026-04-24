//! TCP SYN packet construction and checksum helpers.
//!
//! This module is pure functions over byte slices — no sockets, no I/O.
//! It compiles on every platform so the checksum math is unit-testable
//! in CI without needing `CAP_NET_RAW`.
//!
//! Wire format reference: [RFC 793 §3.1](https://www.rfc-editor.org/rfc/rfc793#section-3.1).

use std::net::Ipv4Addr;

/// Size of a TCP header with no options.
pub const TCP_HEADER_LEN: usize = 20;

/// TCP flag byte values per RFC 793.
pub mod flags {
    pub const FIN: u8 = 0b0000_0001;
    pub const SYN: u8 = 0b0000_0010;
    pub const RST: u8 = 0b0000_0100;
    pub const PSH: u8 = 0b0000_1000;
    pub const ACK: u8 = 0b0001_0000;
    pub const URG: u8 = 0b0010_0000;
}

/// Fields needed to build one SYN.
#[derive(Debug, Clone, Copy)]
pub struct SynSpec {
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
    /// Initial sequence number. Callers should pick this with enough
    /// randomness that replies for stale sprays don't collide with
    /// fresh ones (spec §3.3 on ISN generation).
    pub isn: u32,
    pub window: u16,
}

/// Build a minimal TCP SYN header into `out` (which must be exactly
/// [`TCP_HEADER_LEN`] bytes). The TCP checksum is computed against the
/// IPv4 pseudo-header derived from `spec.src_ip` / `spec.dst_ip`.
///
/// Returns the number of bytes written, which is always
/// `TCP_HEADER_LEN`. Panics if `out.len() != TCP_HEADER_LEN`.
pub fn build_syn_header(spec: &SynSpec, out: &mut [u8]) -> usize {
    assert_eq!(
        out.len(),
        TCP_HEADER_LEN,
        "TCP header buffer must be 20 bytes"
    );

    // src_port (2) | dst_port (2) | seq (4) | ack (4) | data_off+rsv+flags (2)
    // | window (2) | checksum (2) | urgent (2)
    out[0..2].copy_from_slice(&spec.src_port.to_be_bytes());
    out[2..4].copy_from_slice(&spec.dst_port.to_be_bytes());
    out[4..8].copy_from_slice(&spec.isn.to_be_bytes());
    out[8..12].copy_from_slice(&0u32.to_be_bytes());

    // data offset = 5 (20 bytes, no options) << 4 ; low bits = reserved.
    // flags byte follows.
    out[12] = 0x50;
    out[13] = flags::SYN;

    out[14..16].copy_from_slice(&spec.window.to_be_bytes());
    // Checksum: zeroed during computation, filled at end.
    out[16..18].copy_from_slice(&[0, 0]);
    // Urgent pointer.
    out[18..20].copy_from_slice(&0u16.to_be_bytes());

    let csum = tcp_checksum(spec.src_ip, spec.dst_ip, out);
    out[16..18].copy_from_slice(&csum.to_be_bytes());

    TCP_HEADER_LEN
}

/// Compute the TCP checksum over the IPv4 pseudo-header plus the TCP
/// header/payload in `tcp`. The TCP checksum field inside `tcp` must be
/// zeroed before calling this.
pub fn tcp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp: &[u8]) -> u16 {
    // IPv4 pseudo-header:
    //   src_ip (4) | dst_ip (4) | zero (1) | proto=6 (1) | tcp_len (2)
    let mut sum: u32 = 0;

    for pair in src_ip.octets().chunks_exact(2) {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    for pair in dst_ip.octets().chunks_exact(2) {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    sum += 6u32; // protocol (zero byte folded in)
    sum += tcp.len() as u32; // TCP length

    // TCP header + data.
    let mut i = 0;
    while i + 2 <= tcp.len() {
        sum += u16::from_be_bytes([tcp[i], tcp[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp.len() {
        sum += (tcp[i] as u32) << 8;
    }

    // Fold carries.
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Parse a TCP header's flags byte out of a raw TCP segment.
///
/// `tcp.len()` must be at least [`TCP_HEADER_LEN`]. Returns `None` if
/// the slice is too short.
pub fn tcp_flags(tcp: &[u8]) -> Option<u8> {
    tcp.get(13).copied()
}

/// Extract `(src_port, dst_port, ack_number)` from a raw TCP segment.
/// Returns `None` if the slice is too short.
pub fn tcp_ports_and_ack(tcp: &[u8]) -> Option<(u16, u16, u32)> {
    if tcp.len() < 12 {
        return None;
    }
    let src = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst = u16::from_be_bytes([tcp[2], tcp[3]]);
    let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    Some((src, dst, ack))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syn_header_has_expected_shape() {
        let spec = SynSpec {
            src_ip: Ipv4Addr::new(192, 168, 1, 100),
            src_port: 40000,
            dst_ip: Ipv4Addr::new(192, 168, 1, 1),
            dst_port: 80,
            isn: 0x01020304,
            window: 29200,
        };
        let mut buf = [0u8; TCP_HEADER_LEN];
        let n = build_syn_header(&spec, &mut buf);
        assert_eq!(n, TCP_HEADER_LEN);

        assert_eq!(&buf[0..2], &40000u16.to_be_bytes());
        assert_eq!(&buf[2..4], &80u16.to_be_bytes());
        assert_eq!(&buf[4..8], &0x01020304u32.to_be_bytes());
        assert_eq!(&buf[8..12], &[0, 0, 0, 0]);
        assert_eq!(buf[12], 0x50); // data offset 5, reserved 0
        assert_eq!(buf[13], flags::SYN);
        assert_eq!(&buf[14..16], &29200u16.to_be_bytes());
        // Checksum is non-zero.
        assert_ne!(&buf[16..18], &[0u8, 0u8]);
        assert_eq!(&buf[18..20], &0u16.to_be_bytes());
    }

    #[test]
    fn checksum_is_verifiable() {
        // A valid TCP checksum, when recomputed over the same header
        // with the checksum field included, must yield zero (RFC 793).
        let spec = SynSpec {
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            src_port: 12345,
            dst_ip: Ipv4Addr::new(10, 0, 0, 2),
            dst_port: 443,
            isn: 0xDEAD_BEEF,
            window: 0x1234,
        };
        let mut buf = [0u8; TCP_HEADER_LEN];
        build_syn_header(&spec, &mut buf);
        assert_eq!(tcp_checksum(spec.src_ip, spec.dst_ip, &buf), 0);
    }

    #[test]
    fn checksum_is_deterministic() {
        let spec = SynSpec {
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            src_port: 40000,
            dst_ip: Ipv4Addr::new(10, 0, 0, 2),
            dst_port: 443,
            isn: 42,
            window: 29200,
        };
        let mut a = [0u8; TCP_HEADER_LEN];
        let mut b = [0u8; TCP_HEADER_LEN];
        build_syn_header(&spec, &mut a);
        build_syn_header(&spec, &mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn parses_ports_and_ack() {
        let spec = SynSpec {
            src_ip: Ipv4Addr::new(1, 2, 3, 4),
            src_port: 55555,
            dst_ip: Ipv4Addr::new(5, 6, 7, 8),
            dst_port: 22,
            isn: 0,
            window: 0,
        };
        let mut buf = [0u8; TCP_HEADER_LEN];
        build_syn_header(&spec, &mut buf);
        // For a SYN, ack number is zero.
        let (src, dst, ack) = tcp_ports_and_ack(&buf).unwrap();
        assert_eq!(src, 55555);
        assert_eq!(dst, 22);
        assert_eq!(ack, 0);
    }

    #[test]
    fn flags_read_back() {
        let spec = SynSpec {
            src_ip: Ipv4Addr::new(1, 2, 3, 4),
            src_port: 1,
            dst_ip: Ipv4Addr::new(5, 6, 7, 8),
            dst_port: 2,
            isn: 0,
            window: 0,
        };
        let mut buf = [0u8; TCP_HEADER_LEN];
        build_syn_header(&spec, &mut buf);
        assert_eq!(tcp_flags(&buf), Some(flags::SYN));
    }

    #[test]
    fn ports_parse_short_buffer_is_none() {
        let too_short = [0u8; 8];
        assert!(tcp_ports_and_ack(&too_short).is_none());
    }
}
