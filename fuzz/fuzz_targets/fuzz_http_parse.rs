#![no_main]
//! Fuzz HTTP-response parsing used by the passive banner probe.
//!
//! `httparse` is the workhorse in ps-fingerprint's HTTP branch; any
//! panic on adversarial banners would let a hostile upstream kill the
//! fingerprinter task. We feed raw bytes at `httparse::Response::parse`
//! with a generous header budget and require no panics on any input.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);
    let _ = resp.parse(data);

    // Also try request-shaped parses in case a target echoes request
    // bytes back at us (some L4 proxies do exactly this).
    let mut req_headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut req_headers);
    let _ = req.parse(data);
});
