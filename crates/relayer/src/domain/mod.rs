//! One-direction domain modules for IBC v2 packets.
//!
//! Each module decides whether it owns a packet and nothing else. The worker
//! in [`worker`] queries the commitment proof, updates the counterparty
//! client, and submits `MsgRecvPacket` or `MsgAcknowledgement`. When the
//! Penumbra destination client does not exist yet, the same shielded
//! transaction creates it and registers the Cosmos counterparty. A module does
//! not listen, sign, or choose a chain. That split is the same shape as the
//! Cosmos proof API's `ProofApiModule`: one type per source/destination
//! domain, registered in a list, with the service around it staying generic.

pub mod dex_quote;
pub mod open_client;
pub mod wire;
pub mod worker;

use wire::Packet;

/// A domain that wants recv and ack relay for its own payloads.
pub trait DomainModule: Send + Sync {
    /// Short name used in logs.
    fn name(&self) -> &'static str;

    /// Whether this module owns the packet's single payload.
    fn accepts(&self, packet: &Packet) -> bool;
}

/// Modules consulted, in order. The first accept wins.
pub fn modules() -> &'static [&'static dyn DomainModule] {
    &[&dex_quote::DexQuote]
}

/// The module that owns `packet`, if any.
pub fn owner<'a>(packet: &Packet) -> Option<&'a dyn DomainModule> {
    modules().iter().copied().find(|module| module.accepts(packet))
}
