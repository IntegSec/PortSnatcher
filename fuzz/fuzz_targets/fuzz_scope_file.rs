#![no_main]
//! Fuzz the scope-file JSON deserializer.
//!
//! The scope file is operator-supplied and consumed unconditionally at
//! engagement start; a crash in the parser would be a trivial DoS. We
//! drive every byte sequence at `ScopeFile`'s JSON deserializer and
//! require that it never panics.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<ps_core::scope::file::ScopeFile>(data);
});
