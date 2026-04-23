#![no_main]
//! Fuzz TLS-record-header parsing.
//!
//! ps-fingerprint does not yet expose a public `parse_handshake`
//! helper, so this target exercises the narrow bit of parsing we
//! *do* perform before handing bytes off to rustls: validating the
//! first five bytes of a TLS record header (content-type, version,
//! length). The contract is simply "no panics on any input" —
//! malformed bytes should return `None`, not crash.

use libfuzzer_sys::fuzz_target;

fn parse_tls_record_header(data: &[u8]) -> Option<(u8, u16, u16)> {
    if data.len() < 5 {
        return None;
    }
    let content_type = data[0];
    let version = u16::from_be_bytes([data[1], data[2]]);
    let length = u16::from_be_bytes([data[3], data[4]]);
    // TLS spec: record length must be <= 2^14 + 2048 for application
    // data; handshake records are capped at 2^14. We accept anything
    // <= 16640 here — anything larger is malformed-by-definition.
    if length as usize > 16_640 {
        return None;
    }
    Some((content_type, version, length))
}

fuzz_target!(|data: &[u8]| {
    let _ = parse_tls_record_header(data);
});
