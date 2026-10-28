//! IBC v2 packet bytes, commitments, and the two relay messages.
//!
//! Field numbers and the commitment hash match ibc-go `04-channel/v2` and
//! Penumbra's `v2::commitment`. The fixed test vectors below are those
//! projects' vectors, so a one-byte drift fails here before a packet is sent.

use prost::Message;
use sha2::{Digest, Sha256};

use ibc_proto::ibc::core::client::v1::Height as RawHeight;
use ibc_proto::ibc::core::commitment::v1::MerkleProof as RawMerkleProof;

const COMMITMENT_VERSION: u8 = 0x02;
const COMMITMENT_SEPARATOR: u8 = 0x01;
const ACK_SEPARATOR: u8 = 0x03;

/// Cosmos SDK store path for an IBC key. Penumbra's verifiable store is
/// `state/key` with the `ibc-data/` prefix already on the key.
pub const COSMOS_IBC_QUERY_PATH: &str = "store/ibc/key";
pub const PENUMBRA_STATE_QUERY_PATH: &str = "state/key";
pub const PENUMBRA_IBC_PREFIX: &[u8] = b"ibc-data/";

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Payload {
    #[prost(string, tag = "1")]
    pub source_port: String,
    #[prost(string, tag = "2")]
    pub destination_port: String,
    #[prost(string, tag = "3")]
    pub version: String,
    #[prost(string, tag = "4")]
    pub encoding: String,
    #[prost(bytes = "vec", tag = "5")]
    pub value: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Packet {
    #[prost(uint64, tag = "1")]
    pub sequence: u64,
    #[prost(string, tag = "2")]
    pub source_client: String,
    #[prost(string, tag = "3")]
    pub destination_client: String,
    #[prost(uint64, tag = "4")]
    pub timeout_timestamp: u64,
    #[prost(message, repeated, tag = "5")]
    pub payloads: Vec<Payload>,
}

impl Packet {
    pub fn payload(&self) -> Result<&Payload, &'static str> {
        if self.payloads.len() != 1 {
            return Err("packet must carry exactly one payload");
        }
        Ok(&self.payloads[0])
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Acknowledgement {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub app_acknowledgements: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgRecvPacket {
    #[prost(message, optional, tag = "1")]
    pub packet: Option<Packet>,
    #[prost(bytes = "vec", tag = "2")]
    pub proof_commitment: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub proof_height: Option<RawHeight>,
    #[prost(string, tag = "4")]
    pub signer: String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgAcknowledgement {
    #[prost(message, optional, tag = "1")]
    pub packet: Option<Packet>,
    #[prost(message, optional, tag = "2")]
    pub acknowledgement: Option<Acknowledgement>,
    #[prost(bytes = "vec", tag = "3")]
    pub proof_acked: Vec<u8>,
    #[prost(message, optional, tag = "4")]
    pub proof_height: Option<RawHeight>,
    #[prost(string, tag = "5")]
    pub signer: String,
}

pub const RECV_TYPE_URL: &str = "/ibc.core.channel.v2.MsgRecvPacket";
pub const ACK_TYPE_URL: &str = "/ibc.core.channel.v2.MsgAcknowledgement";

/// What a `send_packet` or `write_acknowledgement` event asked us to relay.
#[derive(Clone, Debug)]
pub enum Notice {
    Send(Packet),
    WriteAck { packet: Packet, ack: Acknowledgement },
}

pub fn commit_packet(packet: &Packet) -> [u8; 32] {
    let mut app_bytes = Vec::with_capacity(packet.payloads.len() * 32);
    for payload in &packet.payloads {
        app_bytes.extend_from_slice(&hash_payload(payload));
    }
    let mut buf = Vec::with_capacity(1 + 3 * 32);
    buf.push(COMMITMENT_VERSION);
    buf.extend_from_slice(&Sha256::digest(packet.destination_client.as_bytes()));
    buf.extend_from_slice(&Sha256::digest(packet.timeout_timestamp.to_be_bytes()));
    buf.extend_from_slice(&Sha256::digest(&app_bytes));
    Sha256::digest(&buf).into()
}

pub fn commit_acknowledgement(app_acknowledgements: &[Vec<u8>]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + app_acknowledgements.len() * 32);
    buf.push(COMMITMENT_VERSION);
    for ack in app_acknowledgements {
        buf.extend_from_slice(&Sha256::digest(ack));
    }
    Sha256::digest(&buf).into()
}

fn hash_payload(payload: &Payload) -> [u8; 32] {
    let mut buf = Vec::with_capacity(5 * 32);
    buf.extend_from_slice(&Sha256::digest(payload.source_port.as_bytes()));
    buf.extend_from_slice(&Sha256::digest(payload.destination_port.as_bytes()));
    buf.extend_from_slice(&Sha256::digest(payload.version.as_bytes()));
    buf.extend_from_slice(&Sha256::digest(payload.encoding.as_bytes()));
    buf.extend_from_slice(&Sha256::digest(&payload.value));
    Sha256::digest(&buf).into()
}

fn key(client_id: &str, separator: u8, sequence: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(client_id.len() + 1 + 8);
    k.extend_from_slice(client_id.as_bytes());
    k.push(separator);
    k.extend_from_slice(&sequence.to_be_bytes());
    k
}

pub fn packet_commitment_key(client_id: &str, sequence: u64) -> Vec<u8> {
    key(client_id, COMMITMENT_SEPARATOR, sequence)
}

pub fn packet_acknowledgement_key(client_id: &str, sequence: u64) -> Vec<u8> {
    key(client_id, ACK_SEPARATOR, sequence)
}

/// ABCI path and key bytes for the chain that stores `ics24_key`.
pub fn proof_query(penumbra_store: bool, ics24_key: &[u8]) -> (&'static str, Vec<u8>) {
    if penumbra_store {
        let mut key = Vec::with_capacity(PENUMBRA_IBC_PREFIX.len() + ics24_key.len());
        key.extend_from_slice(PENUMBRA_IBC_PREFIX);
        key.extend_from_slice(ics24_key);
        (PENUMBRA_STATE_QUERY_PATH, key)
    } else {
        (COSMOS_IBC_QUERY_PATH, ics24_key.to_vec())
    }
}

pub fn recv_any(
    packet: Packet,
    proof: &RawMerkleProof,
    revision_number: u64,
    revision_height: u64,
    signer: &str,
) -> ibc_proto::google::protobuf::Any {
    let msg = MsgRecvPacket {
        packet: Some(packet),
        proof_commitment: proof.encode_to_vec(),
        proof_height: Some(RawHeight {
            revision_number,
            revision_height,
        }),
        signer: signer.to_string(),
    };
    ibc_proto::google::protobuf::Any {
        type_url: RECV_TYPE_URL.to_string(),
        value: msg.encode_to_vec(),
    }
}

pub fn ack_any(
    packet: Packet,
    acknowledgement: Acknowledgement,
    proof: &RawMerkleProof,
    revision_number: u64,
    revision_height: u64,
    signer: &str,
) -> ibc_proto::google::protobuf::Any {
    let msg = MsgAcknowledgement {
        packet: Some(packet),
        acknowledgement: Some(acknowledgement),
        proof_acked: proof.encode_to_vec(),
        proof_height: Some(RawHeight {
            revision_number,
            revision_height,
        }),
        signer: signer.to_string(),
    };
    ibc_proto::google::protobuf::Any {
        type_url: ACK_TYPE_URL.to_string(),
        value: msg.encode_to_vec(),
    }
}

/// Pull a v2 notice out of one ABCI event. v1 packets do not carry
/// `encoded_packet_hex`, so they return `None`.
pub fn notice_from_event(kind: &str, attributes: &[(&str, &str)]) -> Option<Notice> {
    let packet_hex = attributes
        .iter()
        .find(|(key, _)| *key == "encoded_packet_hex")
        .map(|(_, value)| *value)?;
    let packet_bytes = hex::decode(packet_hex).ok()?;
    let packet = Packet::decode(packet_bytes.as_slice()).ok()?;
    packet.payload().ok()?;
    match kind {
        "send_packet" => Some(Notice::Send(packet)),
        "write_acknowledgement" => {
            let ack_hex = attributes
                .iter()
                .find(|(key, _)| *key == "encoded_acknowledgement_hex")
                .map(|(_, value)| *value)?;
            let ack_bytes = hex::decode(ack_hex).ok()?;
            let ack = Acknowledgement::decode(ack_bytes.as_slice()).ok()?;
            if ack.app_acknowledgements.len() != 1 || ack.app_acknowledgements[0].is_empty() {
                return None;
            }
            Some(Notice::WriteAck { packet, ack })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transfer_payload(value: Vec<u8>) -> Payload {
        Payload {
            source_port: "transfer".into(),
            destination_port: "transfer".into(),
            version: "ics20-1".into(),
            encoding: "application/json".into(),
            value,
        }
    }

    #[test]
    fn packet_commitment_matches_ibc_go_vector() {
        let value = br#"{"denom":"uatom","amount":"1000000","sender":"sender","receiver":"receiver","memo":"memo"}"#.to_vec();
        let packet = Packet {
            sequence: 1,
            source_client: "07-tendermint-0".into(),
            destination_client: "07-tendermint-1".into(),
            timeout_timestamp: 100,
            payloads: vec![transfer_payload(value)],
        };
        assert_eq!(
            hex::encode(commit_packet(&packet)),
            "a096722aa6534040a0efbdae05765132a7b223ad306d6512f3734821bd046505"
        );
    }

    #[test]
    fn ack_commitment_matches_ibc_go_vector() {
        assert_eq!(
            hex::encode(commit_acknowledgement(&[b"some bytes".to_vec()])),
            "f03b4667413e56aaf086663267913e525c442b56fa1af4fa3f3dab9f37044c5b"
        );
    }

    #[test]
    fn keys_match_eureka_vectors() {
        assert_eq!(
            hex::encode(packet_commitment_key("channel-0", 1)),
            "6368616e6e656c2d30010000000000000001"
        );
        assert_eq!(
            hex::encode(packet_acknowledgement_key("channel-2", 3)),
            "6368616e6e656c2d32030000000000000003"
        );
    }

    #[test]
    fn penumbra_query_prefixes_the_ics24_key() {
        let ics = packet_commitment_key("07-tendermint-0", 1);
        let (path, key) = proof_query(true, &ics);
        assert_eq!(path, "state/key");
        assert!(key.starts_with(b"ibc-data/"));
        assert!(key.ends_with(&ics));
        let (cosmos_path, cosmos_key) = proof_query(false, &ics);
        assert_eq!(cosmos_path, "store/ibc/key");
        assert_eq!(cosmos_key, ics);
    }

    #[test]
    fn send_event_round_trips_and_v1_does_not() {
        let packet = Packet {
            sequence: 4,
            source_client: "07-tendermint-0".into(),
            destination_client: "07-tendermint-1".into(),
            timeout_timestamp: 50,
            payloads: vec![Payload {
                source_port: "wasm21oracle".into(),
                destination_port: "dex-quote".into(),
                version: "dex-quote-1".into(),
                encoding: "application/json".into(),
                value: br#"{"market_id":"TERP/UM"}"#.to_vec(),
            }],
        };
        let encoded = hex::encode(packet.encode_to_vec());
        let notice = notice_from_event("send_packet", &[("encoded_packet_hex", &encoded)])
            .expect("v2 send");
        match notice {
            Notice::Send(parsed) => assert_eq!(parsed, packet),
            Notice::WriteAck { .. } => panic!("send parsed as ack"),
        }
        assert!(notice_from_event("send_packet", &[("packet_data_hex", "abcd")]).is_none());
    }

    #[test]
    fn recv_message_uses_the_v2_type_url() {
        let packet = Packet {
            sequence: 1,
            source_client: "07-tendermint-0".into(),
            destination_client: "07-tendermint-1".into(),
            timeout_timestamp: 9,
            payloads: vec![transfer_payload(b"{}".to_vec())],
        };
        let any = recv_any(packet, &RawMerkleProof { proofs: vec![] }, 0, 12, "signer");
        assert_eq!(any.type_url, RECV_TYPE_URL);
        let msg = MsgRecvPacket::decode(any.value.as_slice()).unwrap();
        assert_eq!(msg.proof_height.unwrap().revision_height, 12);
        assert_eq!(msg.signer, "signer");
    }
}
