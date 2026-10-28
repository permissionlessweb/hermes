//! Create the Penumbra client and register its Cosmos counterparty.
//!
//! A dex-quote recv names a destination client that does not exist yet.
//! Penumbra accepts `RegisterCounterparty` only in the same transaction as
//! `CreateClient`. The client is created at the packet proof height, which is
//! the only consensus state `RecvPacket` will verify against.

use prost::Message;

use ibc_proto::ibc::core::client::v1::Height as RawHeight;
use ibc_proto::ibc::core::client::v1::MsgCreateClient as RawMsgCreateClient;
use ibc_proto::ibc::core::commitment::v1::MerkleRoot;
use ibc_proto::ibc::lightclients::tendermint::v1::{
    ClientState as RawTmClientState, ConsensusState as RawTmConsensusState, Fraction,
};
use ibc_relayer_types::core::ics24_host::identifier::ChainId;
use tendermint_proto::google::protobuf::{Any as TmAny, Duration, Timestamp};

pub const CREATE_CLIENT_TYPE_URL: &str = "/ibc.core.client.v1.MsgCreateClient";
pub const REGISTER_COUNTERPARTY_TYPE_URL: &str = "/ibc.core.client.v2.MsgRegisterCounterparty";

/// Header fields the destination client must store at the proof height.
pub struct ProofHeader {
    pub chain_id: String,
    pub height: u64,
    pub time_seconds: i64,
    pub time_nanos: i32,
    pub app_hash: Vec<u8>,
    pub next_validators_hash: Vec<u8>,
}

/// `CreateClient` at `header.height`, then `RegisterCounterparty`.
///
/// The counterparty prefix is the Cosmos IBC store (`ibc`, empty). Penumbra's
/// own store prefix `ibc-data` is what Terp registers, not this message.
#[allow(deprecated)]
pub fn open_counterparty_anys(
    header: &ProofHeader,
    client_id: &str,
    counterparty_client_id: &str,
    signer: &str,
) -> Result<Vec<ibc_proto::google::protobuf::Any>, String> {
    let revision = ChainId::from_string(&header.chain_id).version();
    let client_state = RawTmClientState {
        chain_id: header.chain_id.clone(),
        trust_level: Some(Fraction {
            numerator: 1,
            denominator: 3,
        }),
        trusting_period: Some(Duration {
            seconds: 14 * 24 * 3600,
            nanos: 0,
        }),
        unbonding_period: Some(Duration {
            seconds: 21 * 24 * 3600,
            nanos: 0,
        }),
        max_clock_drift: Some(Duration {
            seconds: 60,
            nanos: 0,
        }),
        frozen_height: Some(RawHeight {
            revision_number: 0,
            revision_height: 0,
        }),
        latest_height: Some(RawHeight {
            revision_number: revision,
            revision_height: header.height,
        }),
        proof_specs: vec![ics23::iavl_spec(), ics23::tendermint_spec()],
        upgrade_path: vec!["upgrade".into(), "upgradedIBCState".into()],
        allow_update_after_expiry: false,
        allow_update_after_misbehaviour: false,
    };
    let consensus = RawTmConsensusState {
        timestamp: Some(Timestamp {
            seconds: header.time_seconds,
            nanos: header.time_nanos,
        }),
        root: Some(MerkleRoot {
            hash: header.app_hash.clone(),
        }),
        next_validators_hash: header.next_validators_hash.clone(),
    };
    let create = RawMsgCreateClient {
        client_state: Some(TmAny {
            type_url: "/ibc.lightclients.tendermint.v1.ClientState".into(),
            value: client_state.encode_to_vec(),
        }),
        consensus_state: Some(TmAny {
            type_url: "/ibc.lightclients.tendermint.v1.ConsensusState".into(),
            value: consensus.encode_to_vec(),
        }),
        signer: signer.to_string(),
    };
    let register = MsgRegisterCounterparty {
        client_id: client_id.to_string(),
        counterparty_merkle_prefix: vec![b"ibc".to_vec(), Vec::new()],
        counterparty_client_id: counterparty_client_id.to_string(),
        signer: signer.to_string(),
    };
    Ok(vec![
        ibc_proto::google::protobuf::Any {
            type_url: CREATE_CLIENT_TYPE_URL.to_string(),
            value: create.encode_to_vec(),
        },
        ibc_proto::google::protobuf::Any {
            type_url: REGISTER_COUNTERPARTY_TYPE_URL.to_string(),
            value: register.encode_to_vec(),
        },
    ])
}

#[derive(Clone, PartialEq, ::prost::Message)]
struct MsgRegisterCounterparty {
    #[prost(string, tag = "1")]
    client_id: String,
    #[prost(bytes = "vec", repeated, tag = "2")]
    counterparty_merkle_prefix: Vec<Vec<u8>>,
    #[prost(string, tag = "3")]
    counterparty_client_id: String,
    #[prost(string, tag = "4")]
    signer: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_uses_the_proof_height_and_the_cosmos_prefix() {
        let anys = open_counterparty_anys(
            &ProofHeader {
                chain_id: "terp-penumbra-e2e".into(),
                height: 114,
                time_seconds: 1_700_000_000,
                time_nanos: 0,
                app_hash: vec![0x11; 32],
                next_validators_hash: vec![0x22; 32],
            },
            "07-tendermint-1",
            "07-tendermint-0",
            "",
        )
        .unwrap();
        assert_eq!(anys[0].type_url, CREATE_CLIENT_TYPE_URL);
        assert_eq!(anys[1].type_url, REGISTER_COUNTERPARTY_TYPE_URL);
        let create = RawMsgCreateClient::decode(anys[0].value.as_slice()).unwrap();
        let state = RawTmClientState::decode(
            create.client_state.unwrap().value.as_slice(),
        )
        .unwrap();
        assert_eq!(state.latest_height.unwrap().revision_height, 114);
        assert_eq!(state.chain_id, "terp-penumbra-e2e");
        let register = MsgRegisterCounterparty::decode(anys[1].value.as_slice()).unwrap();
        assert_eq!(
            register.counterparty_merkle_prefix,
            vec![b"ibc".to_vec(), Vec::<u8>::new()]
        );
        assert_eq!(register.client_id, "07-tendermint-1");
        assert_eq!(register.counterparty_client_id, "07-tendermint-0");
    }
}
