//! `MongoIsMaster`: send an OP_QUERY for `admin.$cmd {isMaster: 1}`.
//!
//! Any reply whose `messageLength` header field exceeds 16 bytes
//! (the size of the mandatory MsgHeader itself) is treated as a match.

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use ps_core::technique::TechniqueTag;

use super::{Fingerprinter, ProbeContext, ProbeOutcome, Protocol};

const TECHNIQUES: &[TechniqueTag] = &[TechniqueTag::ApiTesting];
const READ_LIMIT: usize = 4096;

/// BSON document `{"isMaster": 1}` as raw bytes (17 bytes).
const IS_MASTER_BSON: &[u8] = &[
    0x11, 0x00, 0x00, 0x00, // document length = 17
    0x10, // element type: int32
    b'i', b's', b'M', b'a', b's', b't', b'e', b'r', 0x00, // key
    0x01, 0x00, 0x00, 0x00, // value = 1 (i32 LE)
    0x00, // document terminator
];

const COLLECTION: &[u8] = b"admin.$cmd\0";

/// Send an OP_QUERY for `{isMaster: 1}` on `admin.$cmd`. A reply longer
/// than the mandatory 16-byte MsgHeader is a confident match.
#[derive(Debug, Default)]
pub struct MongoIsMaster;

#[async_trait]
impl Fingerprinter for MongoIsMaster {
    fn name(&self) -> &'static str {
        "mongo_is_master"
    }

    fn techniques(&self) -> &'static [TechniqueTag] {
        TECHNIQUES
    }

    async fn probe(&self, mut ctx: ProbeContext) -> ProbeOutcome {
        let mut stream = match ctx.stream.take() {
            Some(s) => s,
            None => return ProbeOutcome::Error(anyhow::anyhow!("no stream supplied")),
        };

        let packet = build_packet();
        if let Err(e) = timeout(ctx.timeout, stream.write_all(&packet)).await {
            return ProbeOutcome::Error(anyhow::anyhow!("write timeout: {e}"));
        }

        let mut buf = BytesMut::with_capacity(READ_LIMIT);
        let read = timeout(ctx.timeout, stream.read_buf(&mut buf)).await;
        match read {
            Ok(Ok(0)) => ProbeOutcome::NoMatch,
            Ok(Ok(n)) if n > 16 => {
                let bytes = Bytes::from(buf);
                ProbeOutcome::Match {
                    protocol: Protocol::Mongo,
                    confidence: 0.9,
                    bytes,
                }
            }
            Ok(Ok(_)) => ProbeOutcome::NoMatch,
            Ok(Err(e)) => ProbeOutcome::Error(anyhow::Error::new(e)),
            Err(_) => ProbeOutcome::NoMatch,
        }
    }
}

fn build_packet() -> Vec<u8> {
    // MsgHeader (16 bytes): length, requestID=0, responseTo=0, opCode=2004
    // Body: flags u32=0, fullCollectionName cstring, numberToSkip u32=0,
    //       numberToReturn i32=-1, BSON query document.
    let body_len =
        4 /*flags*/ + COLLECTION.len() + 4 /*skip*/ + 4 /*return*/ + IS_MASTER_BSON.len();
    let total_len = 16 + body_len;

    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&(total_len as u32).to_le_bytes()); // messageLength
    out.extend_from_slice(&0u32.to_le_bytes()); // requestID
    out.extend_from_slice(&0u32.to_le_bytes()); // responseTo
    out.extend_from_slice(&2004u32.to_le_bytes()); // opCode = OP_QUERY
    out.extend_from_slice(&0u32.to_le_bytes()); // flags
    out.extend_from_slice(COLLECTION); // fullCollectionName
    out.extend_from_slice(&0u32.to_le_bytes()); // numberToSkip
    out.extend_from_slice(&(-1i32).to_le_bytes()); // numberToReturn
    out.extend_from_slice(IS_MASTER_BSON);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_has_consistent_length_header() {
        let p = build_packet();
        let declared = u32::from_le_bytes([p[0], p[1], p[2], p[3]]) as usize;
        assert_eq!(declared, p.len());
        // Sanity: opCode at offset 12 is 2004 (OP_QUERY).
        let opcode = u32::from_le_bytes([p[12], p[13], p[14], p[15]]);
        assert_eq!(opcode, 2004);
    }
}
