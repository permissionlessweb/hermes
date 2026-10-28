//! Dex-quote domain. Penumbra is the destination. The packet asks for a
//! position quote and the acknowledgement carries `p` and `q`.

use super::wire::Packet;
use super::DomainModule;

pub const PORT: &str = "dex-quote";
pub const VERSION: &str = "dex-quote-1";
pub const ENCODING: &str = "application/json";

pub struct DexQuote;

impl DomainModule for DexQuote {
    fn name(&self) -> &'static str {
        "dex-quote"
    }

    fn accepts(&self, packet: &Packet) -> bool {
        let Ok(payload) = packet.payload() else {
            return false;
        };
        if payload.destination_port != PORT
            || payload.version != VERSION
            || payload.encoding != ENCODING
        {
            return false;
        }
        is_quote_body(&payload.value)
    }
}

/// A single quote object or a `{"quotes":[...]}` batch. Anything else on
/// this port is left for a different module.
fn is_quote_body(value: &[u8]) -> bool {
    let Ok(body) = serde_json::from_slice::<serde_json::Value>(value) else {
        return false;
    };
    let Some(object) = body.as_object() else {
        return false;
    };
    if let Some(quotes) = object.get("quotes") {
        return quotes
            .as_array()
            .is_some_and(|rows| !rows.is_empty() && rows.len() <= 16);
    }
    object.get("market_id").and_then(|id| id.as_str()).is_some()
}

#[cfg(test)]
mod tests {
    use super::super::wire::{Packet, Payload};
    use super::*;

    fn packet(value: &str) -> Packet {
        Packet {
            sequence: 1,
            source_client: "07-tendermint-0".into(),
            destination_client: "07-tendermint-1".into(),
            timeout_timestamp: 1_700_000_000,
            payloads: vec![Payload {
                source_port: "wasm21oracle".into(),
                destination_port: PORT.into(),
                version: VERSION.into(),
                encoding: ENCODING.into(),
                value: value.as_bytes().to_vec(),
            }],
        }
    }

    #[test]
    fn single_and_batch_quotes_are_ours() {
        assert!(DexQuote.accepts(&packet(
            r#"{"market_id":"TERP/UM","height":"10","pair":{"asset_1":"transfer/channel-0/uterp","asset_2":"penumbra"},"position_id":""}"#
        )));
        assert!(DexQuote.accepts(&packet(
            r#"{"quotes":[{"market_id":"TERP/UM"},{"market_id":"TERP/THIOL"}]}"#
        )));
    }

    #[test]
    fn transfer_and_empty_batch_are_not() {
        let mut transfer = packet(r#"{"denom":"uatom","amount":"1"}"#);
        transfer.payloads[0].destination_port = "transfer".into();
        transfer.payloads[0].version = "ics20-1".into();
        assert!(!DexQuote.accepts(&transfer));
        assert!(!DexQuote.accepts(&packet(r#"{"quotes":[]}"#)));
        assert!(!DexQuote.accepts(&packet("[]")));
    }
}
