// This file is part of midnight-ledger.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: Apache-2.0

use base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};
use coin_structure::coin::{Commitment, Info as CoinInfo, Nullifier, PublicKey as CoinPublicKey};
use coin_structure::transfer::SenderEvidence;
use ledger::events::{Event, EventDetails};
use ledger::structure::{ProofMarker, StandardTransaction, Transaction};
use onchain_runtime::ops::{Key, Op};
use onchain_runtime::program_fragments::Cell_write;
use onchain_runtime::result_mode::ResultModeVerify;
use onchain_runtime::state::StateValue;
use rand::Rng;
use rand::rngs::OsRng;
use serde_json::json;
use serialize::{Deserializable, Tagged, tagged_deserialize, tagged_serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};
use storage::arena::Sp;
use storage::db::InMemoryDB;
use storage::storage::HashMap as StorageHashMap;
use transient_crypto::commitment::{PedersenRandomness, PureGeneratorPedersen};
use transient_crypto::curve::Fr;
use transient_crypto::encryption;
use transient_crypto::proofs::{
    KeyLocation, ParamsProver, ParamsProverProvider, Proof, ProofPreimage, ProvingKeyMaterial,
    Resolver,
};
use transient_crypto::repr::FieldRepr;
use zkir::LocalProvingProvider;
use zswap::keys::{SecretKeys, Seed};
use zswap::ledger::State as ZswapLedgerState;
use zswap::prove::ZswapResolver;
use zswap::{Delta, Input, Offer as ZswapOffer, Output as ZswapOutput, split_coin_binding_tag};

pub type PreviewResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const CLIENT_DERIVATION_KEY_LOCATION: &str = "split/client/sk-derivation";
/// v3: one-time-per-wallet attestation circuit. Mirror of
/// `split-prove-prototype::attestation::WALLET_ATTESTATION_KEY_LOCATION`.
const WALLET_ATTESTATION_KEY_LOCATION: &str = "split/wallet/attestation";
/// v3 Poseidon `C_sk` separator. Must match the immediate loaded in
/// `circuits/wallet_attestation.compact` and `circuits/sk_proof.compact`.
const SK_COMMIT_SEPARATOR: &str = "midnight:sk-commit[v1]";
const DEFAULT_PREVIEW_TRANSFER_AMOUNT: u128 = 500 * 1_000_000;

pub fn split_nullifier(coin: &CoinInfo, sk: &coin_structure::coin::SecretKey) -> Nullifier {
    coin.nullifier(&SenderEvidence::User(Cow::Borrowed(sk)))
}

pub struct PreviewSplitProveOptions<'a> {
    pub proof_server_url: &'a str,
    pub event_limit: Option<usize>,
    pub request_timeout_secs: u64,
}

#[derive(Debug, Default, Clone)]
pub struct PreviewSplitProveTimings {
    pub scan: Duration,
    pub derive_total: Duration,
    pub derive_local_proving: Duration,
    pub handoff_total: Duration,
    pub assemble_and_submit: Duration,
    pub server_client_deriv_verify: Option<Duration>,
    pub server_split_prove: Option<Duration>,
    pub server_total: Option<Duration>,
}

impl PreviewSplitProveTimings {
    pub fn network_overhead(&self) -> Option<Duration> {
        self.server_total
            .and_then(|s| self.handoff_total.checked_sub(s))
    }

    pub fn split_proof_total(&self) -> Option<Duration> {
        self.server_split_prove
            .and_then(|server| self.derive_local_proving.checked_add(server))
    }

    pub fn handoff_non_proving(&self) -> Option<Duration> {
        self.server_split_prove
            .and_then(|server| self.handoff_total.checked_sub(server))
    }

    pub fn wall_clock(&self) -> Duration {
        self.scan + self.derive_total + self.handoff_total + self.assemble_and_submit
    }
}

#[derive(Debug)]
pub struct PreviewSplitProveReport {
    pub key_index: usize,
    pub mt_index: u64,
    pub coin_value: String,
    pub transfer_value: String,
    pub change_value: String,
    pub token_type_hex: String,
    pub recipient_shielded_address: String,
    pub status: String,
    pub proof_hex_len: usize,
    pub tx_hash: String,
    pub tx_id: Option<String>,
    pub tx_hex_len: usize,
    pub block_hash: String,
    pub inclusion_status: String,
    pub well_formed: String,
    pub response: serde_json::Value,
    pub submission: serde_json::Value,
    pub verification: serde_json::Value,
    pub timings: PreviewSplitProveTimings,
}

pub struct PreviewWalletSpend {
    pub key_index: usize,
    pub key: SecretKeys,
    pub coin: CoinInfo,
    pub commitment: Commitment,
    pub nullifier: Nullifier,
    pub mt_index: u64,
    pub zswap_state: ZswapLedgerState<InMemoryDB>,
}

pub fn print_staged_report(report: &PreviewSplitProveReport) {
    let t = &report.timings;
    let ms = |d: Duration| d.as_millis();
    let opt_ms = |d: Option<Duration>| {
        d.map(|d| format!("{} ms", d.as_millis()))
            .unwrap_or_else(|| "n/a".to_string())
    };
    let handoff_ms = ms(t.handoff_total);
    let net_overhead = t
        .network_overhead()
        .map(|d| format!("{} ms", d.as_millis()))
        .unwrap_or_else(|| "n/a".to_string());
    let proof_total = opt_ms(t.split_proof_total());
    let handoff_non_proving = opt_ms(t.handoff_non_proving());
    let wall = ms(t.wall_clock());
    let ratio = match (t.server_split_prove, t.derive_local_proving.as_millis()) {
        (Some(s), c) if c > 0 => format!("{:.2}x", s.as_millis() as f64 / c as f64),
        _ => "n/a".to_string(),
    };

    println!();
    println!("=== split-prove live e2e ===");
    println!();
    println!("--- Proof-only comparison (split-prove work) ---");
    println!(
        "  client proof:  clientDerivationProof (local)        {:>6} ms",
        ms(t.derive_local_proving)
    );
    println!(
        "  server proof:  spend-split proof (remote)           {:>6}",
        opt_ms(t.server_split_prove)
    );
    println!(
        "  split-prove proving total                           {:>6}",
        proof_total
    );
    println!(
        "  ratio (server proof / client proof)                 {:>6}",
        ratio
    );
    println!();
    println!("--- CLIENT (wallet, local) ---");
    println!(
        "  [1/6] scan       events replayed, coin selected          {:>6} ms",
        ms(t.scan)
    );
    println!(
        "  [2/6] derive     client-derivation proof built           {:>6} ms",
        ms(t.derive_total)
    );
    println!(
        "         └─ of which local proving                        {:>6} ms",
        ms(t.derive_local_proving)
    );
    println!(
        "  [5/6] assemble+  recipient output, dust balance, submit  {:>6} ms",
        ms(t.assemble_and_submit)
    );
    println!("         └─ baseline wallet tx work; excluded from proof-only comparison");
    println!();
    println!("--- SERVER (proof-server, remote) ---");
    println!(
        "  [3/6] handoff    POST /v2/prove-split-spend              {:>6} ms total",
        handoff_ms
    );
    println!(
        "         ├─ network (round-trip overhead)                 {:>6}",
        net_overhead
    );
    println!(
        "         ├─ server: verify client derivation proof        {:>6}",
        opt_ms(t.server_client_deriv_verify)
    );
    println!(
        "         └─ server: split-spend proving                   {:>6}",
        opt_ms(t.server_split_prove)
    );
    println!();
    println!("--- NODE + INDEXER ---");
    println!("  [6/6] submit     author_submitAndWatchExtrinsic          (bundled in [5/6])");
    println!("         inclusion_status:  {}", report.inclusion_status);
    println!("         well_formed:       {}", report.well_formed);
    println!("         block_hash:        {}", report.block_hash);
    println!();
    println!("--- End-to-end context (not proof comparison) ---");
    println!(
        "  handoff non-proving time (network + server verify)       {:>6}",
        handoff_non_proving
    );
    println!(
        "  tx assembly, output proof, Dust balance, submit          {:>6} ms",
        ms(t.assemble_and_submit)
    );
    println!(
        "  full demo wall-clock (scan → included tx)                {:>6} ms",
        wall
    );
    println!();
    println!("--- Role boundary check ---");
    println!("  sk crossed the wire?                                    NO");
    println!("  r (attestation blinding) crossed the wire?              NO");
    println!("  what crossed (ClientHandoff): coinBindingTag, nullifier, pk,");
    println!("                commitmentHash, coinValue, coinType, coinNonce,");
    println!("                mtIndex, contractAddress, clientDerivationProof,");
    println!("                attestedCommitmentSk, attestationProof");
    println!();
}

pub async fn prove_preview_wallet_split_spend(
    options: PreviewSplitProveOptions<'_>,
) -> PreviewResult<PreviewSplitProveReport> {
    let env = preview_env();
    let secret_keys = preview_zswap_secret_keys_scan(&env)?;
    let event_limit = options.event_limit.unwrap_or_else(|| {
        env_value(&env, "MIDNIGHT_PREVIEW_ZSWAP_EVENT_LIMIT")
            .parse()
            .unwrap_or(50_000)
    });
    let mut timings = PreviewSplitProveTimings::default();

    tracing::info!(stage = "scan", role = "client", "▶ CLIENT/scan");
    let scan_start = Instant::now();
    let wallet_spend = select_preview_wallet_spend(&secret_keys, &env, event_limit)?;
    timings.scan = scan_start.elapsed();
    tracing::info!(
        stage = "scan",
        role = "client",
        elapsed_ms = timings.scan.as_millis() as u64,
        "✓ CLIENT/scan"
    );

    let transfer_value = preview_transfer_amount(&env, wallet_spend.coin.value)?;

    tracing::info!(stage = "derive", role = "client", "▶ CLIENT/derive");
    let derive_start = Instant::now();
    let (handoff, proving_elapsed) = build_split_spend_handoff_timed(&wallet_spend).await?;
    timings.derive_total = derive_start.elapsed();
    timings.derive_local_proving = proving_elapsed;
    tracing::info!(
        stage = "derive",
        role = "client",
        elapsed_ms = timings.derive_total.as_millis() as u64,
        local_proving_ms = proving_elapsed.as_millis() as u64,
        "✓ CLIENT/derive"
    );

    tracing::info!(
        stage = "handoff",
        role = "client-server",
        "▶ HANDOFF POST /v2/prove-split-spend"
    );
    let handoff_start = Instant::now();
    let body = post_split_spend_handoff(
        options.proof_server_url,
        handoff,
        options.request_timeout_secs,
    )
    .await?;
    timings.handoff_total = handoff_start.elapsed();
    tracing::info!(
        stage = "handoff",
        role = "client-server",
        elapsed_ms = timings.handoff_total.as_millis() as u64,
        "✓ HANDOFF"
    );

    timings.server_client_deriv_verify = body["serverClientDerivVerifyMs"]
        .as_u64()
        .map(Duration::from_millis);
    timings.server_split_prove = body["serverSplitProveMs"]
        .as_u64()
        .map(Duration::from_millis);
    timings.server_total = body["serverTotalMs"].as_u64().map(Duration::from_millis);

    let recipient = decode_preview_recipient(&env)?;

    tracing::info!(
        stage = "assemble-submit",
        role = "client-node",
        "▶ CLIENT/assemble + NODE/submit"
    );
    let submit_start = Instant::now();
    let submission = submit_split_send_transaction(
        &env,
        options.proof_server_url,
        &wallet_spend,
        &body,
        &recipient,
        transfer_value,
    )
    .await?;
    timings.assemble_and_submit = submit_start.elapsed();
    tracing::info!(
        stage = "assemble-submit",
        role = "client-node",
        elapsed_ms = timings.assemble_and_submit.as_millis() as u64,
        "✓ assemble + submit"
    );

    let proof_hex_len = body["proofHex"].as_str().map(str::len).unwrap_or_default();
    let change_value = wallet_spend.coin.value - transfer_value;

    tracing::info!(
        stage = "onchain-verify",
        role = "node",
        "▶ NODE/independent on-chain verification"
    );
    let verify_start = Instant::now();
    let verification = verify_onchain_inclusion(&env, &submission)?;
    tracing::info!(
        stage = "onchain-verify",
        role = "node",
        elapsed_ms = verify_start.elapsed().as_millis() as u64,
        block_number = verification["blockNumber"].as_u64().unwrap_or_default(),
        finalized_depth = verification["finalizedDepth"].as_i64().unwrap_or_default(),
        "✓ independent on-chain verification"
    );

    Ok(PreviewSplitProveReport {
        key_index: wallet_spend.key_index,
        mt_index: wallet_spend.mt_index,
        coin_value: wallet_spend.coin.value.to_string(),
        transfer_value: transfer_value.to_string(),
        change_value: change_value.to_string(),
        token_type_hex: hex::encode(wallet_spend.coin.type_.0.0),
        recipient_shielded_address: recipient.address,
        status: body["status"].as_str().unwrap_or_default().to_string(),
        proof_hex_len,
        tx_hash: submission["txHash"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        tx_id: submission["txId"].as_str().map(str::to_string),
        tx_hex_len: submission["balancedTxHex"]
            .as_str()
            .map(str::len)
            .unwrap_or_default(),
        block_hash: submission["blockHash"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        inclusion_status: submission["inclusionStatus"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        well_formed: submission["wellFormed"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        response: body,
        submission,
        verification,
        timings,
    })
}

fn verify_onchain_inclusion(
    env: &HashMap<String, String>,
    submission: &serde_json::Value,
) -> PreviewResult<serde_json::Value> {
    let block_hash = submission["blockHash"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("submission missing blockHash; cannot verify on-chain inclusion")?;
    let inner_tx_hex = submission["balancedTxHex"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("submission missing balancedTxHex; cannot verify on-chain inclusion")?;
    let tx_id = submission["txId"].as_str().unwrap_or("");

    let output = Command::new("node")
        .arg(repo_root_tool("tools/preview_verify_onchain.mjs")?)
        .arg("--block-hash")
        .arg(block_hash)
        .arg("--inner-tx-hex")
        .arg(inner_tx_hex)
        .arg("--tx-id")
        .arg(tx_id)
        .envs(env.iter())
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "independent on-chain verification failed: stderr={} stdout={}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout),
        )
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn select_preview_wallet_spend(
    secret_keys: &[(usize, SecretKeys)],
    env: &HashMap<String, String>,
    event_limit: usize,
) -> PreviewResult<PreviewWalletSpend> {
    let preview_events = fetch_preview_zswap_events(env, event_limit)?;
    let mut zswap_state = ZswapLedgerState::<InMemoryDB>::new();
    let mut spent_nullifiers = Vec::new();
    let mut owned_outputs = Vec::new();

    for raw in preview_events {
        let event_bytes = hex::decode(raw)?;
        let event: Event<InMemoryDB> = tagged_deserialize(&event_bytes[..])?;

        match event.content {
            EventDetails::ZswapInput { nullifier, .. } => {
                zswap_state.nullifiers = zswap_state.nullifiers.insert(nullifier, ());
                spent_nullifiers.push(nullifier);
            }
            EventDetails::ZswapOutput {
                commitment,
                contract,
                preimage_evidence,
                mt_index,
            } => {
                if mt_index != zswap_state.first_free {
                    return Err(format!(
                        "preview zswap replay expected mt_index {}, got {mt_index}",
                        zswap_state.first_free
                    )
                    .into());
                }
                zswap_state.coin_coms = zswap_state
                    .coin_coms
                    .update_hash(mt_index, commitment.0, contract)
                    .rehash();
                zswap_state.coin_coms_set = zswap_state.coin_coms_set.insert(commitment, ());
                zswap_state.first_free = mt_index + 1;

                if let Some((key_index, key, coin)) =
                    secret_keys.iter().find_map(|(key_index, key)| {
                        preimage_evidence
                            .try_with_keys(key)
                            .map(|coin| (*key_index, key, coin))
                    })
                {
                    let nullifier = split_nullifier(&coin, &key.coin_secret_key);
                    owned_outputs.push((
                        key_index,
                        key.clone(),
                        coin,
                        commitment,
                        nullifier,
                        mt_index,
                    ));
                }
            }
            _ => {}
        }
    }

    let (key_index, key, coin, commitment, nullifier, mt_index) = owned_outputs
        .into_iter()
        .filter(|(_, _, _, _, nullifier, _)| !spent_nullifiers.contains(nullifier))
        .max_by_key(|(_, _, coin, _, _, _)| coin.value)
        .ok_or("preview wallet has no unspent shielded outputs in scanned events")?;

    Ok(PreviewWalletSpend {
        key_index,
        key,
        coin,
        commitment,
        nullifier,
        mt_index,
        zswap_state,
    })
}

pub async fn build_split_spend_handoff(
    spend: &PreviewWalletSpend,
) -> PreviewResult<serde_json::Value> {
    let (value, _) = build_split_spend_handoff_timed(spend).await?;
    Ok(value)
}

pub async fn build_split_spend_handoff_timed(
    spend: &PreviewWalletSpend,
) -> PreviewResult<(serde_json::Value, Duration)> {
    let mut zswap_state_bytes = Vec::new();
    tagged_serialize(&spend.zswap_state, &mut zswap_state_bytes)?;
    let pk = spend.key.coin_secret_key.public_key();
    let coin_binding_tag = split_coin_binding_tag(&spend.coin, pk);

    // v3: one-time wallet attestation. In a real wallet this is generated at
    // registration time and reused across every spend; the preview e2e
    // generates it fresh per run so the demo is self-contained.
    let attestation_start = Instant::now();
    let attestation = prove_wallet_attestation(&spend.key.coin_secret_key).await?;
    let attestation_elapsed = attestation_start.elapsed();

    debug_assert_eq!(attestation.pk, pk, "attestation pk must match the spend's pk");

    let proving_start = Instant::now();
    let client_derivation_proof =
        prove_client_derivation(spend, coin_binding_tag, pk, &attestation).await?;
    let client_derivation_elapsed = proving_start.elapsed();

    // The user-facing `derive_local_proving` timing counts only the per-spend
    // client proof — the attestation is a one-time setup cost, not a per-spend
    // proof, so we don't roll it in. We still log it so it's visible.
    tracing::info!(
        stage = "wallet-attestation",
        role = "client",
        elapsed_ms = attestation_elapsed.as_millis() as u64,
        "✓ CLIENT/wallet-attestation (one-time)"
    );

    Ok((
        json!({
            "coinBindingTag": hex::encode(coin_binding_tag.0.to_bytes_le()),
            "nullifier": hex::encode(spend.nullifier.0.0),
            "pk": hex::encode(pk.0.0),
            "commitmentHash": hex::encode(spend.commitment.0.0),
            "coinValue": spend.coin.value,
            "coinType": hex::encode(spend.coin.type_.0.0),
            "coinNonce": hex::encode(spend.coin.nonce.0.0),
            "mtIndex": spend.mt_index,
            "contractAddress": null,
            "zswapState": hex::encode(zswap_state_bytes),
            "prove": true,
            "clientDerivationProof": hex::encode(client_derivation_proof.0),
            // v3 additions — required by the proof server's /v2/prove-split-spend
            // endpoint and by the node admission verifier.
            "attestedCommitmentSk": hex::encode(attestation.commitment_sk.0.to_bytes_le()),
            "attestationProof": hex::encode(attestation.proof.0),
        }),
        client_derivation_elapsed,
    ))
}

async fn post_split_spend_handoff(
    proof_server_url: &str,
    handoff: serde_json::Value,
    request_timeout_secs: u64,
) -> PreviewResult<serde_json::Value> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(request_timeout_secs))
        .build()?;
    let response = client
        .post(format!("{proof_server_url}/v2/prove-split-spend"))
        .json(&handoff)
        .send()
        .await?;
    let status = response.status();
    let body: serde_json::Value = response.json().await?;
    if !status.is_success() {
        return Err(format!("proof server returned {status}: {body}").into());
    }
    Ok(body)
}

struct PreviewRecipient {
    address: String,
    coin_public_key: CoinPublicKey,
    encryption_public_key: encryption::PublicKey,
}

fn decode_preview_recipient(env: &HashMap<String, String>) -> PreviewResult<PreviewRecipient> {
    let address = env_value(env, "MIDNIGHT_PREVIEW_RECIPIENT_SHIELDED_ADDRESS");
    if address.trim().is_empty() {
        return Err("set MIDNIGHT_PREVIEW_RECIPIENT_SHIELDED_ADDRESS for split-send e2e".into());
    }
    let network_id = env_value_or(env, "MIDNIGHT_PREVIEW_NETWORK_ID", "preview");
    let output = Command::new("node")
        .arg(repo_root_tool(
            "tools/decode_midnight_shielded_address.mjs",
        )?)
        .arg("--address")
        .arg(address.trim())
        .arg("--network-id")
        .arg(&network_id)
        .envs(env.iter())
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "decode recipient shielded address failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    let decoded: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let coin_public_key = deserialize_hex(
        decoded["coinPublicKey"]
            .as_str()
            .ok_or("decoded recipient missing coinPublicKey")?,
    )?;
    let encryption_public_key = deserialize_hex(
        decoded["encryptionPublicKey"]
            .as_str()
            .ok_or("decoded recipient missing encryptionPublicKey")?,
    )?;

    Ok(PreviewRecipient {
        address: address.trim().to_string(),
        coin_public_key,
        encryption_public_key,
    })
}

async fn submit_split_send_transaction(
    env: &HashMap<String, String>,
    proof_server_url: &str,
    spend: &PreviewWalletSpend,
    split_response: &serde_json::Value,
    recipient: &PreviewRecipient,
    transfer_value: u128,
) -> PreviewResult<serde_json::Value> {
    if env_value(env, "MIDNIGHT_PREVIEW_RECOVERY_PHRASE")
        .trim()
        .is_empty()
    {
        return Err(
            "set MIDNIGHT_PREVIEW_RECOVERY_PHRASE for full split-send e2e submission".into(),
        );
    }

    let input_preimage_hex = split_response["inputPreimageHex"]
        .as_str()
        .ok_or("split response missing inputPreimageHex")?;
    let proved_input_hex = split_response["provedInputHex"]
        .as_str()
        .ok_or("split response missing provedInputHex")?;
    let input_preimage: Input<ProofPreimage, InMemoryDB> =
        deserialize_tagged_hex(input_preimage_hex)?;
    let proved_input: Input<Proof, InMemoryDB> = deserialize_tagged_hex(proved_input_hex)?;
    let change_value = spend.coin.value - transfer_value;
    let recipient_coin = CoinInfo::new(&mut OsRng, transfer_value, spend.coin.type_);
    let recipient_output = ZswapOutput::new(
        &mut OsRng,
        &recipient_coin,
        None,
        &recipient.coin_public_key,
        Some(recipient.encryption_public_key),
    )?;
    let mut output_preimages = vec![recipient_output];
    if change_value > 0 {
        let change_coin = CoinInfo::new(&mut OsRng, change_value, spend.coin.type_);
        output_preimages.push(ZswapOutput::new(
            &mut OsRng,
            &change_coin,
            None,
            &spend.key.coin_public_key(),
            Some(spend.key.enc_public_key()),
        )?);
    }

    let mut output_proofs = Vec::with_capacity(output_preimages.len());
    for output_preimage in &output_preimages {
        output_proofs.push(prove_zswap_output(output_preimage).await?);
    }
    proved_input
        .well_formed(0)
        .map_err(|e| format!("server split input proof is not well formed: {e}"))?;
    for (index, output_proof) in output_proofs.iter().enumerate() {
        output_proof
            .well_formed(0)
            .map_err(|e| format!("zswap output proof {index} is not well formed: {e}"))?;
    }

    let deltas = std::iter::once(Delta {
        token_type: spend.coin.type_,
        value: spend.coin.value.try_into().unwrap_or(i128::MAX),
    })
    .chain(output_preimages.iter().map(ZswapOutput::delta))
    .collect();
    let binding_randomness = output_preimages
        .iter()
        .fold(input_preimage.binding_randomness(), |acc, output| {
            acc + output.binding_randomness()
        });
    let mut unproven_offer = ZswapOffer {
        inputs: vec![input_preimage].into(),
        outputs: output_preimages.into(),
        transient: vec![].into(),
        deltas,
    };
    unproven_offer.normalize();

    let mut proven_offer = ZswapOffer {
        inputs: vec![proved_input].into(),
        outputs: output_proofs.into(),
        transient: vec![].into(),
        deltas: unproven_offer.deltas.clone(),
    };
    proven_offer.normalize();

    let tx: Transaction<
        base_crypto::signatures::Signature,
        ProofMarker,
        PedersenRandomness,
        InMemoryDB,
    > = Transaction::Standard(StandardTransaction {
        network_id: env_value_or(env, "MIDNIGHT_PREVIEW_NETWORK_ID", "preview"),
        intents: StorageHashMap::new(),
        guaranteed_coins: Some(Sp::new(proven_offer)),
        fallible_coins: StorageHashMap::new(),
        binding_randomness,
    });
    let sealed: Transaction<
        base_crypto::signatures::Signature,
        ProofMarker,
        PureGeneratorPedersen,
        InMemoryDB,
    > = tx.seal(OsRng);
    let mut tx_bytes = Vec::new();
    tagged_serialize(&sealed, &mut tx_bytes)?;
    let tx_hex = hex::encode(tx_bytes);

    let output = Command::new("node")
        .arg(repo_root_tool("tools/preview_balance_submit_split_tx.mjs")?)
        .arg("--tx-hex")
        .arg(tx_hex)
        .arg("--key-index")
        .arg(spend.key_index.to_string())
        .arg("--proof-server-url")
        .arg(proof_server_url)
        .arg("--submit")
        .envs(env.iter())
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "split-send balance/submit failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    Ok(serde_json::from_slice(&output.stdout)?)
}

fn preview_transfer_amount(env: &HashMap<String, String>, coin_value: u128) -> PreviewResult<u128> {
    let raw = env_value(env, "MIDNIGHT_PREVIEW_TRANSFER_AMOUNT");
    let transfer_value = if raw.trim().is_empty() {
        DEFAULT_PREVIEW_TRANSFER_AMOUNT
    } else {
        raw.trim().parse::<u128>().map_err(|e| {
            format!("MIDNIGHT_PREVIEW_TRANSFER_AMOUNT must be a positive integer: {e}")
        })?
    };

    if transfer_value == 0 {
        return Err("MIDNIGHT_PREVIEW_TRANSFER_AMOUNT must be greater than zero".into());
    }
    if transfer_value > coin_value {
        return Err(format!(
            "MIDNIGHT_PREVIEW_TRANSFER_AMOUNT ({transfer_value}) exceeds selected shielded coin value ({coin_value})"
        )
        .into());
    }

    Ok(transfer_value)
}

async fn prove_zswap_output(
    output: &ZswapOutput<ProofPreimage, InMemoryDB>,
) -> PreviewResult<ZswapOutput<Proof, InMemoryDB>> {
    let resolver = ZswapResolver(
        MidnightDataProvider::new(
            FetchMode::OnDemand,
            OutputMode::Log,
            zswap::ZSWAP_EXPECTED_FILES.to_vec(),
        )
        .map_err(|e| format!("data provider initialization failed: {e}"))?,
    );
    let provider = LocalProvingProvider {
        rng: OsRng,
        params: &resolver,
        resolver: &resolver,
    };
    output
        .prove(provider)
        .await
        .map_err(|e| format!("zswap recipient output proof failed: {e}").into())
}

fn deserialize_tagged_hex<T: Deserializable + Tagged>(value: &str) -> PreviewResult<T> {
    let bytes = hex::decode(value.trim().trim_start_matches("0x"))?;
    Ok(tagged_deserialize(&bytes[..])?)
}

fn deserialize_hex<T: Deserializable>(value: &str) -> PreviewResult<T> {
    let bytes = hex::decode(value.trim().trim_start_matches("0x"))?;
    Ok(T::deserialize(&mut &bytes[..], 0)?)
}

pub fn preview_env() -> HashMap<String, String> {
    let mut values = HashMap::new();
    for (key, value) in std::env::vars() {
        if key.starts_with("MIDNIGHT_PREVIEW_") {
            values.insert(key, value);
        }
    }
    for path in dotenv_candidates() {
        if let Ok(contents) = fs::read_to_string(path) {
            for (key, value) in parse_dotenv(&contents) {
                values.entry(key).or_insert(value);
            }
        }
    }
    values
}

fn env_value(env: &HashMap<String, String>, key: &str) -> String {
    env.get(key).cloned().unwrap_or_default()
}

fn env_value_or(env: &HashMap<String, String>, key: &str, default: &str) -> String {
    let value = env_value(env, key);
    if value.trim().is_empty() {
        default.to_string()
    } else {
        value
    }
}

fn fetch_preview_zswap_events(
    env: &HashMap<String, String>,
    limit: usize,
) -> PreviewResult<Vec<String>> {
    let endpoint = env_value(env, "MIDNIGHT_PREVIEW_INDEXER_WS");
    let endpoint = if endpoint.trim().is_empty() {
        "wss://indexer.preview.midnight.network/api/v4/graphql/ws".to_string()
    } else {
        endpoint
    };
    let endpoint_json = serde_json::to_string(&endpoint)?;
    let script = format!(
        r#"
const limit = {limit};
const endpoint = {endpoint_json};
const ws = new WebSocket(endpoint, 'graphql-transport-ws');
const raws = [];
const fail = (message) => {{
  console.error(message);
  try {{ ws.close(); }} catch {{}}
  setTimeout(() => process.exit(1), 20);
}};
const finish = () => {{
  console.log(JSON.stringify(raws));
  try {{ ws.close(); }} catch {{}}
  setTimeout(() => process.exit(0), 20);
}};
const timer = setTimeout(() => fail('timed out waiting for preview zswap events'), 20000);
ws.addEventListener('open', () => {{
  ws.send(JSON.stringify({{ type: 'connection_init' }}));
}});
ws.addEventListener('message', (event) => {{
  const msg = JSON.parse(String(event.data));
  if (msg.type === 'connection_ack') {{
    ws.send(JSON.stringify({{
      id: 'preview-zswap-events',
      type: 'subscribe',
      payload: {{
        query: 'subscription ($id: Int) {{ zswapLedgerEvents(id: $id) {{ id maxId raw }} }}',
        variables: {{ id: 1 }},
      }},
    }}));
  }} else if (msg.type === 'next') {{
    const item = msg.payload?.data?.zswapLedgerEvents;
    if (item?.raw) raws.push(item.raw);
    if (raws.length >= limit || item?.id >= item?.maxId) {{
      clearTimeout(timer);
      finish();
    }}
  }} else if (msg.type === 'error') {{
    clearTimeout(timer);
    fail(JSON.stringify(msg));
  }}
}});
ws.addEventListener('error', (event) => {{
  clearTimeout(timer);
  fail(event.message || 'websocket error');
}});
"#
    );
    let output = Command::new("node").arg("-e").arg(script).output()?;
    if !output.status.success() {
        return Err(format!(
            "preview indexer fetch failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    Ok(serde_json::from_slice(&output.stdout)?)
}

fn preview_zswap_secret_keys_scan(
    env: &HashMap<String, String>,
) -> PreviewResult<Vec<(usize, SecretKeys)>> {
    let scan_limit = env_value(env, "MIDNIGHT_PREVIEW_ZSWAP_KEY_SCAN_LIMIT")
        .parse()
        .unwrap_or(1);
    (0..scan_limit)
        .map(|index| preview_zswap_secret_keys(env, index).map(|key| (index, key)))
        .collect()
}

fn preview_zswap_secret_keys(
    env: &HashMap<String, String>,
    index: usize,
) -> PreviewResult<SecretKeys> {
    let seed_hex = env_value(env, "MIDNIGHT_PREVIEW_ZSWAP_SEED_HEX");
    let seed_hex = if seed_hex.trim().is_empty() {
        derive_preview_zswap_seed_hex(env, index)?
    } else {
        seed_hex
    };
    let seed_bytes = hex::decode(seed_hex.trim())?;
    let seed_array: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| "zswap seed must be exactly 32 bytes")?;
    Ok(SecretKeys::from(Seed::from(seed_array)))
}

async fn prove_client_derivation(
    spend: &PreviewWalletSpend,
    coin_binding_tag: Fr,
    pk: CoinPublicKey,
    attestation: &PreviewWalletAttestation,
) -> PreviewResult<transient_crypto::proofs::Proof> {
    let preimage = build_client_derivation_preimage(spend, coin_binding_tag, pk, attestation);
    let resolver = ClientDerivationResolver::new(ZswapResolver(
        MidnightDataProvider::new(
            FetchMode::OnDemand,
            OutputMode::Log,
            zswap::ZSWAP_EXPECTED_FILES.to_vec(),
        )
        .map_err(|e| format!("data provider initialization failed: {e}"))?,
    ));
    let (proof, _) = preimage
        .prove::<zkir::IrSource>(OsRng, &resolver, &resolver)
        .await
        .map_err(|e| format!("client derivation proof failed: {e}"))?;
    Ok(proof)
}

fn build_client_derivation_preimage(
    spend: &PreviewWalletSpend,
    coin_binding_tag: Fr,
    pk: CoinPublicKey,
    attestation: &PreviewWalletAttestation,
) -> ProofPreimage {
    // v3 witness layout matches `circuits/sk_proof.compact`'s parameter
    // declaration order: (sk, pk, r, coin).
    let mut inputs = Vec::new();
    spend.key.coin_secret_key.0.0.field_repr(&mut inputs); // sk → 2 Fr limbs
    pk.0.0.field_repr(&mut inputs); // pk → 2 Fr limbs
    inputs.push(attestation.blinding); // r → 1 Fr
    spend.coin.nonce.0.0.field_repr(&mut inputs); // coin.nonce → 2 Fr limbs
    spend.coin.type_.0.0.field_repr(&mut inputs); // coin.color → 2 Fr limbs
    spend.coin.value.field_repr(&mut inputs); // coin.value → 1 Fr

    ProofPreimage {
        inputs,
        private_transcript: Vec::new(),
        public_transcript_inputs: client_derivation_public_transcript_inputs(
            pk,
            spend.nullifier.0.0,
            coin_binding_tag,
            attestation.commitment_sk,
        ),
        public_transcript_outputs: Vec::new(),
        binding_input: 0.into(),
        communications_commitment: None,
        key_location: KeyLocation(Cow::Borrowed(CLIENT_DERIVATION_KEY_LOCATION)),
    }
}

fn client_derivation_public_transcript_inputs(
    pk: CoinPublicKey,
    nullifier: [u8; 32],
    coin_binding_tag: Fr,
    commitment_sk: Fr,
) -> Vec<Fr> {
    let mut inputs = Vec::new();
    extend_ops(
        &mut inputs,
        Cell_write!([Key::Value(0u8.into())], false, CoinPublicKey, pk),
    );
    extend_ops(
        &mut inputs,
        Cell_write!([Key::Value(1u8.into())], false, [u8; 32], nullifier),
    );
    extend_ops(
        &mut inputs,
        Cell_write!([Key::Value(2u8.into())], false, Fr, coin_binding_tag),
    );
    // v3 cell 3 — Poseidon C_sk; cross-checked by the admission verifier
    // against the attestation's commitment_sk public output.
    extend_ops(
        &mut inputs,
        Cell_write!([Key::Value(3u8.into())], false, Fr, commitment_sk),
    );
    inputs
}

/// v3 wallet attestation produced once at the start of a preview run and
/// reused for every spend in that run. Mirrors
/// `split-prove-prototype::attestation::WalletAttestation`.
#[derive(Debug, Clone)]
pub(crate) struct PreviewWalletAttestation {
    pub pk: CoinPublicKey,
    pub commitment_sk: Fr,
    pub blinding: Fr,
    pub proof: Proof,
}

/// Off-circuit derivation of `(pk, C_sk)` from `(sk, r)`. Byte-identical to
/// what the attestation circuit computes — Compact decomposes `Bytes<32>` into
/// an 8-bit limb followed by a 248-bit limb, the same two Fr values
/// `sk.0.0.field_repr()` produces here.
fn derive_attestation_outputs(
    sk: &coin_structure::coin::SecretKey,
    r: Fr,
) -> (CoinPublicKey, Fr) {
    let pk = sk.public_key();
    let mut sk_limbs = Vec::new();
    sk.0.0.field_repr(&mut sk_limbs);
    debug_assert_eq!(sk_limbs.len(), 2, "Bytes<32> must produce 2 Fr limbs");
    let sep = ascii_to_fr_le(SK_COMMIT_SEPARATOR);
    let commitment_sk = transient_crypto::hash::transient_hash(&[sep, sk_limbs[0], sk_limbs[1], r]);
    (pk, commitment_sk)
}

fn ascii_to_fr_le(s: &str) -> Fr {
    let bytes = s.as_bytes();
    debug_assert!(bytes.len() <= 32, "domain separator too long for one Fr");
    let mut buf = [0u8; 32];
    buf[..bytes.len()].copy_from_slice(bytes);
    Fr::from_le_bytes(&buf).expect("ascii fits in Fr")
}

fn build_wallet_attestation_preimage(
    sk: &coin_structure::coin::SecretKey,
    r: Fr,
    pk: CoinPublicKey,
    commitment_sk: Fr,
) -> ProofPreimage {
    let mut inputs = Vec::new();
    sk.0.0.field_repr(&mut inputs);
    inputs.push(r);
    ProofPreimage {
        inputs,
        private_transcript: Vec::new(),
        public_transcript_inputs: wallet_attestation_public_transcript_inputs(pk, commitment_sk),
        public_transcript_outputs: Vec::new(),
        binding_input: 0.into(),
        communications_commitment: None,
        key_location: KeyLocation(Cow::Borrowed(WALLET_ATTESTATION_KEY_LOCATION)),
    }
}

fn wallet_attestation_public_transcript_inputs(
    pk: CoinPublicKey,
    commitment_sk: Fr,
) -> Vec<Fr> {
    let mut inputs = Vec::new();
    extend_ops(
        &mut inputs,
        Cell_write!([Key::Value(0u8.into())], false, CoinPublicKey, pk),
    );
    extend_ops(
        &mut inputs,
        Cell_write!([Key::Value(1u8.into())], false, Fr, commitment_sk),
    );
    inputs
}

/// Generate the per-run wallet attestation. Live e2e runs this once per
/// preview run and reuses the result on every spend; in real wallets this
/// would happen once at setup and persist.
pub(crate) async fn prove_wallet_attestation(
    sk: &coin_structure::coin::SecretKey,
) -> PreviewResult<PreviewWalletAttestation> {
    let r: Fr = OsRng.r#gen();
    let (pk, commitment_sk) = derive_attestation_outputs(sk, r);
    let preimage = build_wallet_attestation_preimage(sk, r, pk, commitment_sk);
    let resolver = ClientDerivationResolver::new(ZswapResolver(
        MidnightDataProvider::new(
            FetchMode::OnDemand,
            OutputMode::Log,
            zswap::ZSWAP_EXPECTED_FILES.to_vec(),
        )
        .map_err(|e| format!("data provider initialization failed: {e}"))?,
    ));
    let (proof, _) = preimage
        .prove::<zkir::IrSource>(OsRng, &resolver, &resolver)
        .await
        .map_err(|e| format!("wallet attestation proof failed: {e}"))?;
    Ok(PreviewWalletAttestation {
        pk,
        commitment_sk,
        blinding: r,
        proof,
    })
}

fn extend_ops<const N: usize>(inputs: &mut Vec<Fr>, ops: [Op<ResultModeVerify, InMemoryDB>; N]) {
    for op in ops.into_iter().filter(|op| match op {
        Op::Idx { path, .. } => !path.is_empty(),
        Op::Ins { n, .. } => *n != 0,
        _ => true,
    }) {
        op.field_repr(inputs);
    }
}

struct ClientDerivationResolver<P> {
    params_and_fallback: P,
}

impl<P> ClientDerivationResolver<P> {
    fn new(params_and_fallback: P) -> Self {
        Self {
            params_and_fallback,
        }
    }
}

impl<P> Resolver for ClientDerivationResolver<P>
where
    P: Resolver + Sync,
{
    async fn resolve_key(&self, key: KeyLocation) -> std::io::Result<Option<ProvingKeyMaterial>> {
        if key.0.as_ref() == CLIENT_DERIVATION_KEY_LOCATION {
            Ok(Some(client_derivation_proving_data()))
        } else if key.0.as_ref() == WALLET_ATTESTATION_KEY_LOCATION {
            Ok(Some(wallet_attestation_proving_data()))
        } else {
            self.params_and_fallback.resolve_key(key).await
        }
    }
}

impl<P> ParamsProverProvider for ClientDerivationResolver<P>
where
    P: ParamsProverProvider + Sync,
{
    async fn get_params(&self, k: u8) -> std::io::Result<ParamsProver> {
        self.params_and_fallback.get_params(k).await
    }
}

fn client_derivation_proving_data() -> ProvingKeyMaterial {
    ProvingKeyMaterial {
        prover_key: include_bytes!("../../../../circuits/static/client-derivation/sk_prove.prover")
            .to_vec(),
        verifier_key: include_bytes!(
            "../../../../circuits/static/client-derivation/sk_prove.verifier"
        )
        .to_vec(),
        ir_source: include_bytes!("../../../../circuits/static/client-derivation/sk_prove.bzkir")
            .to_vec(),
    }
}

fn wallet_attestation_proving_data() -> ProvingKeyMaterial {
    ProvingKeyMaterial {
        prover_key: include_bytes!(
            "../../../../circuits/static/wallet-attestation/wallet_attest.prover"
        )
        .to_vec(),
        verifier_key: include_bytes!(
            "../../../../circuits/static/wallet-attestation/wallet_attest.verifier"
        )
        .to_vec(),
        ir_source: include_bytes!(
            "../../../../circuits/static/wallet-attestation/wallet_attest.bzkir"
        )
        .to_vec(),
    }
}

fn derive_preview_zswap_seed_hex(
    env: &HashMap<String, String>,
    index: usize,
) -> PreviewResult<String> {
    let phrase = env_value(env, "MIDNIGHT_PREVIEW_RECOVERY_PHRASE");
    if phrase.trim().is_empty() {
        return Err(
            "set MIDNIGHT_PREVIEW_RECOVERY_PHRASE or MIDNIGHT_PREVIEW_ZSWAP_SEED_HEX in .env"
                .into(),
        );
    }

    let output = Command::new("node")
        .arg(repo_root_tool("tools/derive_midnight_zswap_seed.mjs")?)
        .env("MIDNIGHT_PREVIEW_RECOVERY_PHRASE", phrase)
        .env(
            "MIDNIGHT_PREVIEW_ACCOUNT",
            env_value(env, "MIDNIGHT_PREVIEW_ACCOUNT"),
        )
        .env("MIDNIGHT_PREVIEW_ZSWAP_KEY_INDEX", index.to_string())
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "wallet derivation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn repo_root_tool(relative_path: &str) -> PreviewResult<PathBuf> {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = dir.join(relative_path);
        if candidate.exists() {
            return Ok(candidate);
        }
        if !dir.pop() {
            return Err(format!("could not find repo root tool: {relative_path}").into());
        }
    }
}

fn dotenv_candidates() -> Vec<PathBuf> {
    let mut candidates = [".env", "../.env", "../../.env", "../../../.env"]
        .into_iter()
        .map(PathBuf::from)
        .collect::<Vec<_>>();

    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        candidates.push(dir.join(".env"));
        if !dir.pop() {
            break;
        }
    }

    candidates
}

fn parse_dotenv(contents: &str) -> impl Iterator<Item = (String, String)> + '_ {
    contents.lines().filter_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let (key, value) = line.split_once('=')?;
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .or_else(|| {
                value
                    .strip_prefix('\'')
                    .and_then(|value| value.strip_suffix('\''))
            })
            .or_else(|| value.strip_prefix('"'))
            .or_else(|| value.strip_prefix('\''))
            .unwrap_or(value);
        Some((key.trim().to_string(), value.to_string()))
    })
}
