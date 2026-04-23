#![no_main]
//! Fuzz the `portsnatcher/v1` event deserializer.
//!
//! Events can be replayed from disk (`jsonl` artefacts), pushed over
//! SSE, or ingested from external tooling. Any panic on malformed
//! input would crash the consumer. This target guarantees the
//! deserializer only ever returns `Err` on bad bytes.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<ps_core::event::Event>(data);
});
