// This file is part of midnight-ledger.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: Apache-2.0

//! Phase 2 wallet → registry contract call.
//!
//! After Phase 1 baked the `wallet_registry` contract into genesis, the
//! wallet must insert its own `reg_leaf` into the contract's
//! `HistoricMerkleTree<20, Bytes<32>>` before its first split spend. This
//! module builds the corresponding unbalanced `Transaction` (a single
//! `register(leaf)` contract call with no Zswap offers and no Dust offer)
//! and serializes it to hex so the JS-side wallet SDK can balance and
//! submit it.
//!
//! Chain reads here go through raw substrate JSON-RPC via `reqwest`. The
//! proof-server crate intentionally does not depend on subxt — that would
//! pull the entire polkadot-sdk dep graph into a crate that does not need
//! it.

use base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};
use base_crypto::fab::AlignedValue;
use base_crypto::hash::HashOutput;
use base_crypto::signatures::Signature;
use base_crypto::time::Timestamp;
use coin_structure::contract::ContractAddress;
use ledger::construct::{ContractCallPrototype, PreTranscript, partition_transcripts};
use ledger::structure::{
    ContractAction, Intent, LedgerParameters, ProofMarker, ProofVersioned, Transaction,
};
use onchain_runtime::context::QueryContext;
use onchain_runtime::cost_model::INITIAL_COST_MODEL;
use onchain_runtime::ops::{Key, Op, key};
use onchain_runtime::program_fragments::HistoricMerkleTree_insert_hash;
use onchain_runtime::result_mode::ResultModeVerify;
use onchain_runtime::state::{ContractOperation, ContractState, EntryPointBuf, StateValue};
use rand::Rng;
use rand::rngs::OsRng;
use serde_json::json;
use serialize::{tagged_deserialize, tagged_serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::ops::Deref;
use std::time::{Duration as StdDuration, SystemTime, UNIX_EPOCH};
use storage::arena::Sp;
use storage::db::InMemoryDB;
use storage::storage::HashMap as StorageHashMap;
use transient_crypto::commitment::{PedersenRandomness, PureGeneratorPedersen};
use transient_crypto::proofs::{KeyLocation, PARAMS_VERIFIER, ProofPreimage, VerifierKey};
use zkir::LocalProvingProvider;
use zswap::prove::ZswapResolver;

use crate::local_poc_client::{
    ClientDerivationResolver, LocalPocResult, REGISTER_KEY_LOCATION, env_value, env_value_or,
};

/// Segment ID for the register-call intent. Segment 0 is reserved for the
/// guaranteed slice; segment 1 carries the fallible work the wallet pays
/// Dust for.
const REGISTER_SEGMENT_ID: u16 = 1;

/// Default transaction time-to-live for the unbalanced register tx, in
/// seconds. The wallet SDK may shorten this when balancing.
const DEFAULT_TX_TTL_SECS: u64 = 1800;

/// Outcome of `build_register_call_tx_hex`.
#[derive(Debug)]
pub enum RegisterCallOutcome {
    /// The wallet's `reg_leaf` is already present in the on-chain registry
    /// tree at the given leaf index. Nothing to submit.
    AlreadyRegistered {
        registry_address: ContractAddress,
        leaf_index: u64,
    },
    /// A fully proven, sealed `register(leaf)` transaction ready for the
    /// wallet SDK to balance and submit.
    TxBuilt {
        registry_address: ContractAddress,
        tx_hex: String,
    },
}

/// Build (and prove) the `register(reg_leaf)` transaction, or return
/// `AlreadyRegistered` if the leaf is already on-chain.
///
/// `env` must carry `MIDNIGHT_LOCAL_NODE_RPC_HTTP` (or fall back to
/// `http://127.0.0.1:9944`) and `MIDNIGHT_LOCAL_NETWORK_ID` (default
/// `undeployed`).
pub async fn build_register_call_tx_hex(
    reg_leaf_bytes: [u8; 32],
    env: &HashMap<String, String>,
) -> LocalPocResult<RegisterCallOutcome> {
    let rpc_url = node_rpc_http_url(env);
    let network_id = env_value_or(env, "MIDNIGHT_LOCAL_NETWORK_ID", "undeployed");

    // Step 1: discover the registry address from on-chain LedgerParameters.
    let ledger_params = fetch_ledger_parameters(&rpc_url).await?;
    let registry_address = ledger_params.split_registry_contract.ok_or_else(|| {
        "chain LedgerParameters.split_registry_contract is None; Phase 1 deploy missing"
    })?;

    // Step 2: fetch the contract's live state.
    let contract_state = fetch_contract_state(&rpc_url, registry_address).await?;

    // Step 3: idempotency — if our leaf already lives in the tree, skip.
    if let Some(idx) = find_leaf_index(&contract_state, reg_leaf_bytes)? {
        tracing::info!(
            registry_address = %hex::encode(registry_address.0.0),
            leaf_index = idx,
            "wallet reg_leaf already registered on-chain; skipping register tx"
        );
        return Ok(RegisterCallOutcome::AlreadyRegistered {
            registry_address,
            leaf_index: idx,
        });
    }

    // Step 4: look up the register entry-point's verifier operation. The
    // chain's operations map is the canonical source for this — it has to
    // match what genesis baked in.
    let register_entry_point: EntryPointBuf = b"register"[..].into();
    let register_op: ContractOperation = contract_state
        .operations
        .get(&register_entry_point)
        .map(|sp: Sp<ContractOperation, InMemoryDB>| sp.deref().clone())
        .ok_or_else(|| {
            format!(
                "registry contract at 0x{} is missing the 'register' operation",
                hex::encode(registry_address.0.0)
            )
        })?;

    // Step 5: build the VM program (the `HistoricMerkleTree_insert_hash`
    // sequence that pushes `reg_leaf_bytes` into the height-20 tree at
    // ledger field index 0).
    let program: Vec<Op<ResultModeVerify, InMemoryDB>> = HistoricMerkleTree_insert_hash!(
        [key!(0u8)],
        false,
        20,
        [u8; 32],
        reg_leaf_bytes
    )
    .into();

    // Step 6: partition the program against the live state to produce
    // guaranteed/fallible transcripts. Use the chain's actual parameters
    // (fees may differ from INITIAL_PARAMETERS).
    let pre_transcript = PreTranscript {
        context: QueryContext::new(contract_state.data.clone(), registry_address),
        program,
        comm_comm: None,
    };
    let transcripts = partition_transcripts(&[pre_transcript], &ledger_params)
        .map_err(|e| format!("partition_transcripts failed: {e:?}"))?;
    let (guaranteed_transcript, fallible_transcript) = transcripts.into_iter().next().ok_or(
        "partition_transcripts produced no transcripts for register call",
    )?;

    let mut rng = OsRng;

    // Step 7: build the call prototype.
    let prototype: ContractCallPrototype<InMemoryDB> = ContractCallPrototype {
        address: registry_address,
        entry_point: register_entry_point,
        op: register_op,
        guaranteed_public_transcript: guaranteed_transcript,
        fallible_public_transcript: fallible_transcript,
        private_transcript_outputs: vec![],
        input: AlignedValue::from(reg_leaf_bytes),
        output: ().into(),
        communication_commitment_rand: rng.r#gen(),
        key_location: KeyLocation(Cow::Borrowed(REGISTER_KEY_LOCATION)),
    };

    // Step 8: wrap in an Intent + Transaction. The Intent has no
    // unshielded offers and no Dust offer at this point — the wallet
    // SDK's `balanceFinalizedTransaction` will graft a Dust offer on
    // when it balances.
    let ttl = compute_ttl(env);
    let intent: Intent<Signature, _, _, InMemoryDB> =
        Intent::empty(&mut rng, ttl).add_call::<ProofPreimage>(prototype);
    let intents = StorageHashMap::<u16, _, InMemoryDB>::new().insert(REGISTER_SEGMENT_ID, intent);
    let unproven_tx: Transaction<Signature, _, PedersenRandomness, InMemoryDB> =
        Transaction::from_intents(network_id.as_str(), intents);

    // Step 9: prove. Resolver hits the wallet-registry compiled artifacts
    // via `register_proving_data()` for `KeyLocation("register")`; the
    // ZswapResolver fallback handles zswap params if asked (it won't be,
    // since there are no Zswap offers here).
    let resolver = ClientDerivationResolver::new(ZswapResolver(
        MidnightDataProvider::new(
            FetchMode::OnDemand,
            OutputMode::Log,
            zswap::ZSWAP_EXPECTED_FILES.to_vec(),
        )
        .map_err(|e| format!("data provider initialization failed: {e}"))?,
    ));
    let provider = LocalProvingProvider {
        rng,
        params: &resolver,
        resolver: &resolver,
    };
    let proven_tx: Transaction<Signature, ProofMarker, PedersenRandomness, InMemoryDB> = unproven_tx
        .prove(provider, &INITIAL_COST_MODEL)
        .await
        .map_err(|e| format!("register call proving failed: {e:?}"))?;

    // Step 10: seal binding randomness and serialize.
    let sealed = proven_tx.seal(OsRng);

    // Step 11: local pre-flight — verify the contract-call proof against
    // the embedded verifier key the same way the chain will. If this
    // fails the chain will reject too (Custom error 115), but here we
    // get the underlying `VerifyingError` instead of the opaque wire code.
    preflight_verify_register_proof(&sealed, &contract_state)?;

    let mut tx_bytes = Vec::new();
    tagged_serialize(&sealed, &mut tx_bytes)?;

    Ok(RegisterCallOutcome::TxBuilt {
        registry_address,
        tx_hex: hex::encode(tx_bytes),
    })
}

/// Verify the register-call proof locally with the same VerifierKey +
/// public inputs the chain uses. Mirrors `ContractCall::well_formed`'s
/// V2 proof check inline. Surfaces the underlying `VerifyingError` on
/// failure (vs the chain's lossy `Custom(115)`).
fn preflight_verify_register_proof(
    tx: &Transaction<Signature, ProofMarker, PureGeneratorPedersen, InMemoryDB>,
    contract_state: &ContractState<InMemoryDB>,
) -> LocalPocResult<()> {
    let stx = match tx {
        Transaction::Standard(stx) => stx,
        _ => return Err("preflight: register tx must be Standard".into()),
    };
    let intent_entry = stx
        .intents
        .iter()
        .find(|seg_intent| *seg_intent.0.deref() == REGISTER_SEGMENT_ID)
        .ok_or("preflight: no intent at segment 1")?;
    let intent = intent_entry.1.deref();
    let parent_binding_com = intent.binding_commitment.commitment;
    let call_action = intent
        .actions
        .iter_deref()
        .find_map(|a| match a {
            ContractAction::Call(sp) => Some(sp.deref().clone()),
            _ => None,
        })
        .ok_or("preflight: intent has no ContractCall action")?;
    let proof = match &call_action.proof {
        ProofVersioned::V2(p) => p,
        #[allow(unreachable_patterns)]
        _ => return Err("preflight: unsupported proof version".into()),
    };

    let embedded_verifier_bytes: &[u8] =
        include_bytes!("../../../../circuits/static/wallet-registry/register.verifier");
    let embedded_vk: VerifierKey = tagged_deserialize(embedded_verifier_bytes)?;

    // Pull the verifier key from the live contract state and compare. If
    // the chain's op has a different key than the one we proved against,
    // verification will obviously fail; surface that explicitly.
    let chain_op = contract_state
        .operations
        .get(&EntryPointBuf::from(&b"register"[..]))
        .map(|sp| sp.deref().clone())
        .ok_or("preflight: chain contract state missing 'register' operation")?;
    let chain_vk = chain_op
        .latest()
        .cloned()
        .ok_or("preflight: chain 'register' op has no verifier key (op.v2 is None)")?;
    let mut embedded_bytes = Vec::new();
    serialize::Serializable::serialize(&embedded_vk, &mut embedded_bytes)?;
    let mut chain_bytes = Vec::new();
    serialize::Serializable::serialize(&chain_vk, &mut chain_bytes)?;
    if embedded_bytes != chain_bytes {
        return Err(format!(
            "preflight: embedded verifier-key bytes ({} bytes) differ from chain op verifier-key ({} bytes)",
            embedded_bytes.len(),
            chain_bytes.len()
        )
        .into());
    }
    tracing::info!(
        embedded_vk_bytes = embedded_bytes.len(),
        chain_vk_matches = true,
        "preflight: verifier-key bytes match between embedded artifact and chain state"
    );

    let pis = call_action.public_inputs(parent_binding_com);
    tracing::info!(
        pis_len = pis.len(),
        binding_input = ?pis.first(),
        comm_com = ?pis.get(1),
        "preflight: computed chain-style PIs"
    );

    // Use the chain's vk (which we've just proved matches the embedded
    // one) — same path the runtime executes.
    chain_vk
        .verify(&PARAMS_VERIFIER, proof, pis.iter().copied())
        .map_err(|e| format!("preflight register-call proof verify failed: {e}"))?;
    Ok(())
}

// ------------------------------------------------------------------ helpers

fn node_rpc_http_url(env: &HashMap<String, String>) -> String {
    let raw = env_value(env, "MIDNIGHT_LOCAL_NODE_RPC_HTTP");
    if raw.trim().is_empty() {
        return "http://127.0.0.1:9944".to_string();
    }
    raw
}

fn compute_ttl(env: &HashMap<String, String>) -> Timestamp {
    let secs: u64 = env_value(env, "MIDNIGHT_LOCAL_TX_TTL_SECS")
        .parse()
        .unwrap_or(DEFAULT_TX_TTL_SECS);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Timestamp::from_secs(now.saturating_add(secs))
}

async fn fetch_ledger_parameters(rpc_url: &str) -> LocalPocResult<LedgerParameters> {
    // SCALE-encoded `Result<Vec<u8>, LedgerApiError>` carrying
    // `tagged_serialize(&LedgerParameters)` bytes on the Ok arm.
    let raw = state_call(rpc_url, "MidnightRuntimeApi_get_ledger_parameters", "0x").await?;
    let bytes = hex_decode_prefixed(&raw)?;
    let inner = scale_decode_result_vec_u8(&bytes)
        .ok_or("state_call returned Err arm for get_ledger_parameters")?;
    let params: LedgerParameters = tagged_deserialize(&inner[..])?;
    Ok(params)
}

async fn fetch_contract_state(
    rpc_url: &str,
    address: ContractAddress,
) -> LocalPocResult<ContractState<InMemoryDB>> {
    let address_hex = hex::encode(address.0.0);
    let raw = json_rpc(rpc_url, "midnight_contractState", json!([address_hex])).await?;
    let result = raw
        .get("result")
        .and_then(|v| v.as_str())
        .ok_or("midnight_contractState response missing result string")?;
    let bytes = hex_decode_prefixed(result)?;
    if bytes.is_empty() {
        return Err(format!(
            "contract state at 0x{address_hex} is empty; registry contract not deployed?"
        )
        .into());
    }
    let state: ContractState<InMemoryDB> = tagged_deserialize(&bytes[..])?;
    Ok(state)
}

/// Walk the registry contract's state and locate `reg_leaf_bytes` if it
/// already lives in the tree.
fn find_leaf_index(
    contract_state: &ContractState<InMemoryDB>,
    reg_leaf_bytes: [u8; 32],
) -> LocalPocResult<Option<u64>> {
    let leaf_hash = HashOutput(reg_leaf_bytes);
    let top = match contract_state.data.get_ref() {
        StateValue::Array(arr) => arr,
        _ => return Err("registry contract data is not a StateValue::Array".into()),
    };
    let historic_tree = match top.get(0) {
        Some(StateValue::Array(arr)) => arr,
        _ => return Err("registry data[0] is not a StateValue::Array (HistoricMerkleTree)".into()),
    };
    let tree = match historic_tree.get(0) {
        Some(StateValue::BoundedMerkleTree(mt)) => mt,
        _ => return Err("registry data[0][0] is not a BoundedMerkleTree".into()),
    };
    for (index, hash) in tree.iter() {
        if hash == leaf_hash {
            return Ok(Some(index));
        }
    }
    Ok(None)
}

// ------------------------------------------------- JSON-RPC + SCALE plumbing

async fn json_rpc(
    rpc_url: &str,
    method: &str,
    params: serde_json::Value,
) -> LocalPocResult<serde_json::Value> {
    let body = json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
    });
    let http_url = ws_to_http(rpc_url);
    let client = reqwest::Client::builder()
        .timeout(StdDuration::from_secs(30))
        .build()?;
    let response = client.post(&http_url).json(&body).send().await?;
    let status = response.status();
    let payload: serde_json::Value = response.json().await?;
    if let Some(err) = payload.get("error") {
        return Err(format!("RPC {method} returned error: {err}").into());
    }
    if !status.is_success() {
        return Err(format!("RPC {method} HTTP {status}: {payload}").into());
    }
    Ok(payload)
}

async fn state_call(rpc_url: &str, name: &str, data_hex: &str) -> LocalPocResult<String> {
    let response = json_rpc(rpc_url, "state_call", json!([name, data_hex])).await?;
    let result = response
        .get("result")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("state_call({name}) response missing result string"))?
        .to_string();
    Ok(result)
}

fn ws_to_http(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("ws://") {
        format!("http://{rest}")
    } else if let Some(rest) = url.strip_prefix("wss://") {
        format!("https://{rest}")
    } else {
        url.to_string()
    }
}

fn hex_decode_prefixed(s: &str) -> LocalPocResult<Vec<u8>> {
    let cleaned = s.trim().trim_start_matches("0x");
    Ok(hex::decode(cleaned)?)
}

/// Decode the SCALE encoding of `Result<Vec<u8>, E>` into the Ok arm's
/// inner bytes. Returns `None` for the Err arm; returns `Err` on a
/// malformed encoding.
fn scale_decode_result_vec_u8(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut cursor = bytes;
    let tag = *cursor.first()?;
    cursor = &cursor[1..];
    if tag != 0 {
        return None;
    }
    let (len, rest) = scale_decode_compact(cursor)?;
    if rest.len() < len {
        return None;
    }
    Some(rest[..len].to_vec())
}

/// Decode a SCALE compact-encoded `u32` length, returning the value and
/// the remaining slice. Supports modes 0, 1, 2 (covers lengths up to
/// 2^30 - 1, far beyond any realistic LedgerParameters blob).
fn scale_decode_compact(bytes: &[u8]) -> Option<(usize, &[u8])> {
    let first = *bytes.first()?;
    match first & 0b11 {
        0 => Some(((first >> 2) as usize, &bytes[1..])),
        1 => {
            if bytes.len() < 2 {
                return None;
            }
            let value = u16::from_le_bytes([bytes[0], bytes[1]]);
            Some(((value >> 2) as usize, &bytes[2..]))
        }
        2 => {
            if bytes.len() < 4 {
                return None;
            }
            let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            Some(((value >> 2) as usize, &bytes[4..]))
        }
        _ => None,
    }
}

