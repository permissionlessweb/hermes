//! Scans new blocks for v2 packets a [`super::DomainModule`] owns and
//! submits the recv or acknowledgement.
//!
//! The scan starts at the current tip. Packets from before the process
//! started are left alone. A packet is retried a few times, then dropped
//! from the queue so a permanent failure does not repeat every tick.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use tokio::runtime::Runtime;
use tracing::{debug, info, warn};

use ibc_proto::ibc::core::commitment::v1::MerkleProof as RawMerkleProof;
use ibc_relayer_types::core::ics02_client::height::Height;
use ibc_relayer_types::core::ics23_commitment::merkle::convert_tm_to_ics_merkle_proof;
use ibc_relayer_types::core::ics24_host::identifier::{ChainId, ClientId};
use tendermint_rpc::{Client as _, HttpClient};

use crate::chain::handle::ChainHandle;
use crate::chain::requests::{IncludeProof, QueryClientStateRequest, QueryHeight};
use crate::chain::tracking::TrackedMsgs;
use crate::config::{ChainConfig, Config};
use crate::foreign_client::ForeignClient;
use crate::registry::SharedRegistry;
use crate::util::task::{spawn_background_task, Next, TaskError, TaskHandle};

use super::open_client::{self, ProofHeader};
use super::owner;
use super::wire::{
    self, commit_acknowledgement, commit_packet, packet_acknowledgement_key, packet_commitment_key,
    Notice,
};

const MAX_ATTEMPTS: u8 = 5;
const BLOCKS_PER_TICK: u64 = 20;

pub fn spawn<C: ChainHandle>(config: Config, registry: SharedRegistry<C>) -> Option<TaskHandle> {
    if !config.mode.packets.enabled {
        return None;
    }
    let runtime = Runtime::new().expect("dex-quote relay runtime");
    let mut progress = Progress::default();
    let chain_ids: Vec<ChainId> = config.chains.iter().map(|chain| chain.id().clone()).collect();

    Some(spawn_background_task(
        tracing::error_span!("worker.domain"),
        Some(Duration::from_secs(2)),
        move || -> Result<Next, TaskError<String>> {
            if let Err(error) = scan(&runtime, &registry, &chain_ids, &mut progress) {
                warn!(%error, "v2 domain scan");
            }
            Ok(Next::Continue)
        },
    ))
}

#[derive(Default)]
struct Progress {
    /// Last block height already scanned, per chain.
    cursors: HashMap<ChainId, u64>,
    attempts: HashMap<String, u8>,
    done: HashSet<String>,
}

fn scan<C: ChainHandle>(
    runtime: &Runtime,
    registry: &SharedRegistry<C>,
    chain_ids: &[ChainId],
    progress: &mut Progress,
) -> Result<(), String> {
    for chain_id in chain_ids {
        if let Err(error) = scan_chain(runtime, registry, chain_id, progress) {
            warn!(%chain_id, %error, "v2 domain scan");
        }
    }
    Ok(())
}

fn scan_chain<C: ChainHandle>(
    runtime: &Runtime,
    registry: &SharedRegistry<C>,
    chain_id: &ChainId,
    progress: &mut Progress,
) -> Result<(), String> {
    let chain = registry
        .get_or_spawn(chain_id)
        .map_err(|error| error.to_string())?;
    let latest = chain
        .query_latest_height()
        .map_err(|error| error.to_string())?
        .revision_height();
    let mut scanned = progress
        .cursors
        .get(chain_id)
        .copied()
        .unwrap_or_else(|| latest.saturating_sub(1));
    if latest <= scanned {
        return Ok(());
    }
    let end = (scanned + BLOCKS_PER_TICK).min(latest);
    let config = chain.config().map_err(|error| error.to_string())?;
    for height in (scanned + 1)..=end {
        let notices = runtime.block_on(notices_at(&config, height))?;
        let pending = notices.into_iter().any(|notice| {
            !relay(runtime, registry, &chain, height, notice, progress)
        });
        if pending {
            progress.cursors.insert(chain_id.clone(), scanned);
            return Ok(());
        }
        scanned = height;
    }
    progress.cursors.insert(chain_id.clone(), scanned);
    Ok(())
}

async fn notices_at(config: &ChainConfig, height: u64) -> Result<Vec<Notice>, String> {
    let client = HttpClient::new(rpc_url(config).clone()).map_err(|error| error.to_string())?;
    let tm_height =
        tendermint::block::Height::try_from(height).map_err(|error| error.to_string())?;
    let response = client
        .block_results(tm_height)
        .await
        .map_err(|error| error.to_string())?;
    let mut notices = Vec::new();
    for event in events_of(&response) {
        let pairs: Vec<(String, String)> = event
            .attributes
            .iter()
            .filter_map(|attribute| {
                Some((
                    attribute.key_str().ok()?.to_string(),
                    attribute.value_str().ok()?.to_string(),
                ))
            })
            .collect();
        let refs: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        if let Some(notice) = wire::notice_from_event(&event.kind, &refs) {
            notices.push(notice);
        }
    }
    Ok(notices)
}

fn events_of(
    response: &tendermint_rpc::endpoint::block_results::Response,
) -> Vec<tendermint::abci::Event> {
    let mut events = Vec::new();
    if let Some(txs) = &response.txs_results {
        for tx in txs {
            events.extend(tx.events.iter().cloned());
        }
    }
    if let Some(begin) = &response.begin_block_events {
        events.extend(begin.iter().cloned());
    }
    if let Some(end) = &response.end_block_events {
        events.extend(end.iter().cloned());
    }
    events.extend(response.finalize_block_events.iter().cloned());
    events
}

/// `true` when this notice needs no further attempt.
fn relay<C: ChainHandle>(
    runtime: &Runtime,
    registry: &SharedRegistry<C>,
    host: &C,
    event_height: u64,
    notice: Notice,
    progress: &mut Progress,
) -> bool {
    let (kind, packet, ack) = match notice {
        Notice::Send(packet) => ("recv", packet, None),
        Notice::WriteAck { packet, ack } => ("ack", packet, Some(ack)),
    };
    if owner(&packet).is_none() {
        return true;
    }
    let key = format!(
        "{kind}:{}:{}:{}:{}",
        host.id(),
        packet.source_client,
        packet.destination_client,
        packet.sequence
    );
    if progress.done.contains(&key) {
        return true;
    }
    let attempts = progress.attempts.entry(key.clone()).or_insert(0);
    if *attempts >= MAX_ATTEMPTS {
        progress.done.insert(key);
        return true;
    }
    *attempts += 1;
    let result = match ack {
        None => submit_recv(runtime, registry, host, event_height, &packet),
        Some(ack) => submit_ack(runtime, registry, host, event_height, &packet, &ack),
    };
    match result {
        Ok(()) => {
            info!(%key, "relayed dex-quote packet");
            progress.done.insert(key);
            true
        }
        Err(error) if already_settled(&error) => {
            debug!(%key, %error, "dex-quote packet already settled");
            progress.done.insert(key);
            true
        }
        Err(error) => {
            warn!(%key, %error, "dex-quote relay failed");
            false
        }
    }
}

fn submit_recv<C: ChainHandle>(
    runtime: &Runtime,
    registry: &SharedRegistry<C>,
    source: &C,
    event_height: u64,
    packet: &wire::Packet,
) -> Result<(), String> {
    let destination_id = tracked_chain(source, &packet.source_client)?;
    let destination = registry
        .get_or_spawn(&destination_id)
        .map_err(|error| error.to_string())?;
    let expected = commit_packet(packet);
    let (proof, proof_height) = commitment_proof(
        runtime,
        source,
        event_height,
        &packet_commitment_key(&packet.source_client, packet.sequence),
        &expected,
    )?;
    let signer = destination
        .get_signer()
        .map_err(|error| error.to_string())?;
    let recv = wire::recv_any(
        packet.clone(),
        &proof,
        proof_height.revision_number(),
        proof_height.revision_height(),
        signer.as_ref(),
    );
    let messages = match tracked_chain(&destination, &packet.destination_client) {
        Ok(back) if back == source.id() => {
            let mut messages =
                client_update(&destination, source, &packet.destination_client, proof_height)?;
            messages.push(recv);
            messages
        }
        Ok(back) => {
            return Err(format!(
                "client {} on {} tracks {back}, not {}",
                packet.destination_client,
                destination.id(),
                source.id()
            ));
        }
        Err(error) => {
            let config = destination.config().map_err(|err| err.to_string())?;
            if !penumbra_store(&config) || !client_absent(&error) {
                return Err(error);
            }
            let next = next_tendermint_client(&destination)?;
            if next != packet.destination_client {
                return Err(format!(
                    "penumbra would assign {next}, packet names {}",
                    packet.destination_client
                ));
            }
            let source_config = source.config().map_err(|err| err.to_string())?;
            let header = runtime.block_on(proof_header(
                rpc_url(&source_config),
                proof_height.revision_height(),
            ))?;
            let mut messages = open_client::open_counterparty_anys(
                &header,
                &packet.destination_client,
                &packet.source_client,
                signer.as_ref(),
            )?;
            messages.push(recv);
            messages
        }
    };
    destination
        .send_messages_and_wait_commit(TrackedMsgs::new_static(messages, "dex-quote"))
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn submit_ack<C: ChainHandle>(
    runtime: &Runtime,
    registry: &SharedRegistry<C>,
    receiver: &C,
    event_height: u64,
    packet: &wire::Packet,
    ack: &wire::Acknowledgement,
) -> Result<(), String> {
    let sender_id = tracked_chain(receiver, &packet.destination_client)?;
    let sender = registry
        .get_or_spawn(&sender_id)
        .map_err(|error| error.to_string())?;
    let expected = commit_acknowledgement(&ack.app_acknowledgements);
    let (proof, proof_height) = commitment_proof(
        runtime,
        receiver,
        event_height,
        &packet_acknowledgement_key(&packet.destination_client, packet.sequence),
        &expected,
    )?;
    let signer = sender.get_signer().map_err(|error| error.to_string())?;
    let message = wire::ack_any(
        packet.clone(),
        ack.clone(),
        &proof,
        proof_height.revision_number(),
        proof_height.revision_height(),
        signer.as_ref(),
    );
    let mut messages = client_update(&sender, receiver, &packet.source_client, proof_height)?;
    messages.push(message);
    sender
        .send_messages_and_wait_commit(TrackedMsgs::new_static(messages, "dex-quote"))
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Chain id stored in `client_id` on `host`.
fn tracked_chain<C: ChainHandle>(host: &C, client_id: &str) -> Result<ChainId, String> {
    let client_id = client_id
        .parse::<ClientId>()
        .map_err(|error| error.to_string())?;
    let (state, _) = host
        .query_client_state(
            QueryClientStateRequest {
                client_id,
                height: QueryHeight::Latest,
            },
            IncludeProof::No,
        )
        .map_err(|error| error.to_string())?;
    Ok(state.chain_id())
}

fn client_absent(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("empty response value")
        || error.contains("not found")
        || error.contains("unknown client")
}

/// First `07-tendermint-N` id `host` does not already store.
fn next_tendermint_client<C: ChainHandle>(host: &C) -> Result<String, String> {
    for n in 0..32u64 {
        let id = format!("07-tendermint-{n}");
        match tracked_chain(host, &id) {
            Ok(_) => continue,
            Err(error) if client_absent(&error) => return Ok(id),
            Err(error) => return Err(error),
        }
    }
    Err("more than 32 tendermint clients".into())
}

async fn proof_header(rpc: &tendermint_rpc::Url, height: u64) -> Result<ProofHeader, String> {
    let client = HttpClient::new(rpc.clone()).map_err(|error| error.to_string())?;
    let tm_height =
        tendermint::block::Height::try_from(height).map_err(|error| error.to_string())?;
    let header = client
        .commit(tm_height)
        .await
        .map_err(|error| error.to_string())?
        .signed_header
        .header;
    let seconds = header.time.unix_timestamp();
    let nanos = header.time.unix_timestamp_nanos();
    let time_nanos = (nanos - i128::from(seconds) * 1_000_000_000) as i32;
    Ok(ProofHeader {
        chain_id: header.chain_id.to_string(),
        height,
        time_seconds: seconds,
        time_nanos,
        app_hash: header.app_hash.as_bytes().to_vec(),
        next_validators_hash: header.next_validators_hash.as_bytes().to_vec(),
    })
}

fn client_update<C: ChainHandle>(
    host: &C,
    target: &C,
    client_id: &str,
    proof_height: Height,
) -> Result<Vec<ibc_proto::google::protobuf::Any>, String> {
    let client_id = client_id
        .parse::<ClientId>()
        .map_err(|error| error.to_string())?;
    let client = ForeignClient::restore(client_id, host.clone(), target.clone());
    client
        .wait_and_build_update_client(proof_height)
        .map_err(|error| error.to_string())
}

fn commitment_proof<C: ChainHandle>(
    runtime: &Runtime,
    chain: &C,
    event_height: u64,
    ics24_key: &[u8],
    expected: &[u8; 32],
) -> Result<(RawMerkleProof, Height), String> {
    let config = chain.config().map_err(|error| error.to_string())?;
    let latest = chain
        .query_latest_height()
        .map_err(|error| error.to_string())?;
    // Header `event_height + 1` carries the app hash of the state written by
    // that block. Wait until the header exists before asking for the proof.
    if latest.revision_height() <= event_height {
        return Err("waiting for the header that commits this packet".to_string());
    }
    let (path, key) = wire::proof_query(penumbra_store(&config), ics24_key);
    let (value, proof) = runtime.block_on(prove(rpc_url(&config), path, key, event_height))?;
    if value.as_slice() != expected {
        return Err(format!(
            "commitment mismatch: store {} expected {}",
            hex::encode(value),
            hex::encode(expected)
        ));
    }
    let proof_height = Height::new(latest.revision_number(), event_height + 1)
        .map_err(|error| error.to_string())?;
    Ok((proof, proof_height))
}

async fn prove(
    rpc: &tendermint_rpc::Url,
    path: &str,
    key: Vec<u8>,
    height: u64,
) -> Result<(Vec<u8>, RawMerkleProof), String> {
    let client = HttpClient::new(rpc.clone()).map_err(|error| error.to_string())?;
    let tm_height =
        tendermint::block::Height::try_from(height).map_err(|error| error.to_string())?;
    let response = client
        .abci_query(Some(path.to_string()), key, Some(tm_height), true)
        .await
        .map_err(|error| error.to_string())?;
    if response.code.value() != 0 {
        return Err(format!("abci query code {}", response.code.value()));
    }
    let proof_ops = response.proof.ok_or_else(|| "empty abci proof".to_string())?;
    let proof = convert_tm_to_ics_merkle_proof(&proof_ops).map_err(|error| error.to_string())?;
    Ok((response.value, RawMerkleProof::from(proof)))
}

fn already_settled(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("already been received")
        || error.contains("already received")
        || (error.contains("acknowledgement") && error.contains("already"))
}

fn penumbra_store(config: &ChainConfig) -> bool {
    match config {
        #[cfg(feature = "penumbra")]
        ChainConfig::Penumbra(_) => true,
        _ => false,
    }
}

fn rpc_url(config: &ChainConfig) -> &tendermint_rpc::Url {
    match config {
        ChainConfig::CosmosSdk(cfg) => &cfg.rpc_addr,
        #[cfg(feature = "namada")]
        ChainConfig::Namada(cfg) => &cfg.rpc_addr,
        #[cfg(feature = "penumbra")]
        ChainConfig::Penumbra(cfg) => &cfg.rpc_addr,
    }
}
