// This file is part of midnight-ledger.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: Apache-2.0

use base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};
use base_crypto::hash::HashOutput;
use coin_structure::coin::{Commitment, Info as CoinInfo, Nullifier, PublicKey as CoinPublicKey};
use coin_structure::transfer::SenderEvidence;
use ledger::events::{Event, EventDetails};
use ledger::structure::{ProofMarker, StandardTransaction, Transaction};
use onchain_runtime::ops::{Key, Op};
use onchain_runtime::program_fragments::Cell_write;
use onchain_runtime::result_mode::ResultModeVerify;
use onchain_runtime::state::StateValue;
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
use transient_crypto::hash::{degrade_to_transient, transient_hash, upgrade_from_transient};
use transient_crypto::merkle_tree::{MerklePath, MerkleTree, MerkleTreeDigest};
use transient_crypto::proofs::{
    KeyLocation, ParamsProver, ParamsProverProvider, Proof, ProofPreimage, ProvingKeyMaterial,
    Resolver,
};
use transient_crypto::repr::FieldRepr;
use zkir::LocalProvingProvider;
use zswap::keys::{SecretKeys, Seed};
use zswap::ledger::State as ZswapLedgerState;
use zswap::prove::ZswapResolver;
use zswap::verify::AcceptAllRegistryRootPolicy;
use zswap::{Delta, Input, Offer as ZswapOffer, Output as ZswapOutput, split_coin_binding_tag};

pub type LocalPocResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const CLIENT_DERIVATION_KEY_LOCATION: &str = "split/client/sk-derivation";
/// Solution A wallet-attestation circuit. In the local POC this is off-chain
/// evidence for the synthetic first-registration witness.
const WALLET_ATTESTATION_KEY_LOCATION: &str = "split/wallet/attestation";
/// Compact-generated key location for `wallet_registry.register(leaf)`. The
/// `compact compile` toolchain stores it under `keys/register.{prover,verifier}`
/// so the `KeyLocation` is the bare circuit name.
pub(crate) const REGISTER_KEY_LOCATION: &str = "register";
/// Domain separator for the Poseidon `C_sk` commitment.
const SK_COMMIT_SEPARATOR: &str = "midnight:sk-commit[v1]";
/// Domain separator for the registration leaf `reg_leaf`.
const REG_LEAF_SEPARATOR: &str = "midnight:wallet-reg[v1]";
/// Domain separator for the deterministic `r` blinding factor derivation.
/// Same wallet seed → same `r` → same `reg_leaf` → reusable across the
/// `register-wallet` and subsequent split-spend runs.
const SK_R_DERIVE_SEPARATOR: &str = "midnight:sk-r-derive[v1]";
/// Domain separator for the deterministic `salt` derivation. See
/// [`SK_R_DERIVE_SEPARATOR`] for rationale.
const SK_SALT_DERIVE_SEPARATOR: &str = "midnight:sk-salt-derive[v1]";
/// Height of the wallet-registry Merkle tree. Mirror of
/// `split_prove::client::REGISTRY_TREE_HEIGHT` and the constant baked into
/// `circuits/wallet_registry.compact` / `sk_proof.compact`.
const REGISTRY_TREE_HEIGHT: u8 = 20;
const DEFAULT_LOCAL_TRANSFER_AMOUNT: u128 = 500 * 1_000_000;

pub fn split_nullifier(coin: &CoinInfo, sk: &coin_structure::coin::SecretKey) -> Nullifier {
    coin.nullifier(&SenderEvidence::User(Cow::Borrowed(sk)))
}

pub struct LocalPocSplitProveOptions<'a> {
    pub proof_server_url: &'a str,
    pub event_limit: Option<usize>,
    pub request_timeout_secs: u64,
}

#[derive(Debug, Default, Clone)]
pub struct LocalPocSplitProveTimings {
    pub scan: Duration,
    pub derive_total: Duration,
    pub derive_local_proving: Duration,
    pub handoff_total: Duration,
    pub assemble_and_submit: Duration,
    pub server_client_deriv_verify: Option<Duration>,
    pub server_split_prove: Option<Duration>,
    pub server_total: Option<Duration>,
}

impl LocalPocSplitProveTimings {
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
pub struct LocalPocSplitProveReport {
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
    pub pre_submit_wasm_check: String,
    pub response: serde_json::Value,
    pub submission: serde_json::Value,
    pub verification: serde_json::Value,
    pub timings: LocalPocSplitProveTimings,
}

pub struct LocalPocWalletSpend {
    pub key_index: usize,
    pub key: SecretKeys,
    pub coin: CoinInfo,
    pub commitment: Commitment,
    pub nullifier: Nullifier,
    pub mt_index: u64,
    pub zswap_state: ZswapLedgerState<InMemoryDB>,
}

pub fn print_staged_report(report: &LocalPocSplitProveReport) {
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
    println!("=== split-prove local-node e2e ===");
    println!();
    println!("--- Proof-only comparison (split-prove work) ---");
    println!(
        "  client proof:  clientDerivationProof (local)        {:>6} ms",
        ms(t.derive_local_proving)
    );
    println!(
        "  server proof:  spend-split proof (proof-server)     {:>6}",
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
    println!("--- SERVER (proof-server) ---");
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
    println!(
        "         pre_submit_wasm_check: {}",
        report.pre_submit_wasm_check
    );
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
        "  full POC wall-clock (scan → included tx)                 {:>6} ms",
        wall
    );
    println!();
    println!("--- Role boundary check ---");
    println!("  sk crossed the wire?                                    NO");
    println!("  r (Poseidon C_sk blinding) crossed the wire?            NO");
    println!("  salt (reg-leaf blinding) crossed the wire?              NO");
    println!("  merkle_path crossed the wire?                           NO");
    println!("  what crossed (ClientHandoff): coinBindingTag, nullifier, pk,");
    println!("                commitmentHash, coinValue, coinType, coinNonce,");
    println!("                mtIndex, contractAddress, clientDerivationProof,");
    println!("                registryRoot");
    println!();
}

pub async fn prove_local_wallet_split_spend(
    options: LocalPocSplitProveOptions<'_>,
) -> LocalPocResult<LocalPocSplitProveReport> {
    let env = local_poc_env();
    let secret_keys = local_zswap_secret_keys_scan(&env)?;
    let event_limit = options.event_limit.unwrap_or_else(|| {
        env_value(&env, "MIDNIGHT_LOCAL_ZSWAP_EVENT_LIMIT")
            .parse()
            .unwrap_or(50_000)
    });
    let mut timings = LocalPocSplitProveTimings::default();

    tracing::info!(stage = "scan", role = "client", "▶ CLIENT/scan");
    let scan_start = Instant::now();
    let wallet_spend = select_local_wallet_spend(&secret_keys, &env, event_limit)?;
    timings.scan = scan_start.elapsed();
    tracing::info!(
        stage = "scan",
        role = "client",
        elapsed_ms = timings.scan.as_millis() as u64,
        "✓ CLIENT/scan"
    );

    let transfer_value = local_transfer_amount(&env, wallet_spend.coin.value)?;

    tracing::info!(stage = "derive", role = "client", "▶ CLIENT/derive");
    let derive_start = Instant::now();
    // `MIDNIGHT_LOCAL_FORCE_CORRUPT_REGISTRY_WITNESS=1` is the Phase 4
    // negative-control hook: build a corrupted synthetic witness (real leaf
    // at index 0 + dummy at index 1) so the resulting `registryRoot` is a tree
    // root the chain never held — it is absent from the registry contract's
    // historic-roots set. The per-spend proof itself is well-formed, so the
    // proof-server roundtrip succeeds — but ledger admission MUST reject the
    // bundle with `SplitRegistryRootNotRecognized` (this is what proves the
    // dev-accept-all bypass is actually off). Note admission now accepts ANY
    // historic root, so the corrupt root is rejected because it was never
    // registered, not merely because it differs from the current root.
    let force_corrupt = env_value(&env, "MIDNIGHT_LOCAL_FORCE_CORRUPT_REGISTRY_WITNESS") == "1";
    let (handoff, proving_elapsed) = if force_corrupt {
        tracing::warn!(
            "negative-control: MIDNIGHT_LOCAL_FORCE_CORRUPT_REGISTRY_WITNESS=1 \
             — using corrupted-synthetic registry witness; admission MUST reject with \
             SplitRegistryRootNotRecognized unless MIDNIGHT_SPLIT_REGISTRY_DEV_ACCEPT_ALL=1 \
             is masking the check"
        );
        // Use the same BIP39-derived `(r, salt)` as the chain witness path
        // so the wallet's `reg_leaf` still matches what's registered
        // on-chain — only the path/root is corrupted, not the leaf itself.
        build_split_spend_handoff_inner(
            &wallet_spend,
            RegistryWitnessSource::CorruptSynthetic,
            &env,
        )
        .await?
    } else {
        build_split_spend_handoff_with_chain_witness_timed(&wallet_spend, &env).await?
    };
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

    let recipient = decode_local_recipient(&env)?;

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

    Ok(LocalPocSplitProveReport {
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
        pre_submit_wasm_check: submission["preSubmitWasmCheck"]
            .as_str()
            .or_else(|| submission["wellFormed"].as_str())
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
) -> LocalPocResult<serde_json::Value> {
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
        .arg(repo_root_tool("tools/local_verify_onchain.mjs")?)
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

fn select_local_wallet_spend(
    secret_keys: &[(usize, SecretKeys)],
    env: &HashMap<String, String>,
    event_limit: usize,
) -> LocalPocResult<LocalPocWalletSpend> {
    let local_events = fetch_local_zswap_events(env, event_limit)?;
    let mut zswap_state = ZswapLedgerState::<InMemoryDB>::new();
    let mut spent_nullifiers = Vec::new();
    let mut owned_outputs = Vec::new();

    for raw in local_events {
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
                        "local zswap replay expected mt_index {}, got {mt_index}",
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
        .ok_or("local wallet has no unspent shielded outputs in scanned events")?;

    Ok(LocalPocWalletSpend {
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
    spend: &LocalPocWalletSpend,
) -> LocalPocResult<serde_json::Value> {
    let (value, _) = build_split_spend_handoff_timed(spend).await?;
    Ok(value)
}

pub async fn build_split_spend_handoff_timed(
    spend: &LocalPocWalletSpend,
) -> LocalPocResult<(serde_json::Value, Duration)> {
    let empty_env = HashMap::new();
    build_split_spend_handoff_inner(spend, RegistryWitnessSource::Synthetic, &empty_env).await
}

/// Chain-aware variant of [`build_split_spend_handoff`]: reads the live
/// `wallet_registry` contract state and builds the spend witness against
/// the real Merkle root, instead of a synthetic single-leaf tree.
///
/// Requires the local node to be reachable (`MIDNIGHT_LOCAL_NODE_RPC_HTTP`
/// env or default `http://127.0.0.1:9944`) and the wallet's `reg_leaf` to
/// already be present on-chain (i.e. `make register-wallet` has run for
/// this seed).
pub async fn build_split_spend_handoff_with_chain_witness(
    spend: &LocalPocWalletSpend,
    env: &HashMap<String, String>,
) -> LocalPocResult<serde_json::Value> {
    let (value, _) =
        build_split_spend_handoff_with_chain_witness_timed(spend, env).await?;
    Ok(value)
}

pub async fn build_split_spend_handoff_with_chain_witness_timed(
    spend: &LocalPocWalletSpend,
    env: &HashMap<String, String>,
) -> LocalPocResult<(serde_json::Value, Duration)> {
    build_split_spend_handoff_inner(spend, RegistryWitnessSource::Chain(env), env).await
}

/// Selector for which registry tree to derive the membership witness
/// against.
///
/// - `Synthetic`: legacy single-leaf in-memory tree. Used by the
///   proof-server's synthetic integration tests (no chain required) and,
///   coincidentally, matches the chain whenever the chain has a single
///   leaf registered at index 0 — handy for tests, NOT useful as a
///   negative control.
/// - `CorruptSynthetic`: single real leaf at index 0 + a dummy at index 1.
///   The resulting tree root is one the chain never registered, so it is
///   absent from the registry contract's historic-roots set and admission
///   rejects with `SplitRegistryRootNotRecognized` (proves the dev-accept-all
///   bypass is off). The per-spend proof itself is still well-formed.
/// - `Chain`: queries the live `wallet_registry` contract via RPC and
///   produces a path whose root equals the chain's current registry root
///   (which is, of course, a member of the historic-roots set).
enum RegistryWitnessSource<'a> {
    Synthetic,
    CorruptSynthetic,
    Chain(&'a HashMap<String, String>),
}

async fn build_split_spend_handoff_inner<'a>(
    spend: &LocalPocWalletSpend,
    source: RegistryWitnessSource<'a>,
    env_for_attestation: &HashMap<String, String>,
) -> LocalPocResult<(serde_json::Value, Duration)> {
    let mut zswap_state_bytes = Vec::new();
    tagged_serialize(&spend.zswap_state, &mut zswap_state_bytes)?;
    let pk = spend.key.coin_secret_key.public_key();
    let coin_binding_tag = split_coin_binding_tag(&spend.coin, pk);

    // Solution A wallet registration. Same wallet seed → same `(r, salt)` →
    // same `reg_leaf`, both on the initial `register-wallet` run and every
    // subsequent split spend. When a BIP39 recovery phrase is reachable via
    // `env_for_attestation`, `(r, salt)` are derived via HKDF-SHA256 over
    // the BIP39 seed (production-shaped); the synthetic test paths fall
    // back to Poseidon-over-sk so they work with `StdRng`-seeded keys.
    let attestation_start = Instant::now();
    let registration = prove_wallet_attestation(
        &spend.key.coin_secret_key,
        env_for_attestation,
        spend.key_index,
    )
    .await?;
    let attestation_elapsed = attestation_start.elapsed();

    let registry_witness = match source {
        RegistryWitnessSource::Synthetic => build_first_registration_witness(&registration)?,
        RegistryWitnessSource::CorruptSynthetic => {
            build_corrupt_registration_witness(&registration)?
        }
        RegistryWitnessSource::Chain(env) => {
            crate::wallet_registry_call::build_chain_registration_witness(
                registration.reg_leaf_bytes,
                env,
            )
            .await?
        }
    };

    let proving_start = Instant::now();
    let client_derivation_proof = prove_client_derivation(
        spend,
        coin_binding_tag,
        pk,
        &registration,
        &registry_witness,
    )
    .await?;
    let client_derivation_elapsed = proving_start.elapsed();

    // The user-facing `derive_local_proving` timing counts only the per-spend
    // client proof — the attestation is a one-time setup cost, not a
    // per-spend proof, so we don't roll it in. We still log it so it's
    // visible.
    tracing::info!(
        stage = "wallet-attestation",
        role = "client",
        elapsed_ms = attestation_elapsed.as_millis() as u64,
        "✓ CLIENT/wallet-attestation (one-time)"
    );

    let registry_root_hex = hex::encode(registry_witness.registry_root.0.as_le_bytes());

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
            // Solution A: the only wallet-identifying public input is the
            // registry root the per-spend membership path resolves to. The
            // bundle no longer carries pk / attested_commitment_sk /
            // attestation_proof.
            "registryRoot": registry_root_hex,
        }),
        client_derivation_elapsed,
    ))
}

async fn post_split_spend_handoff(
    proof_server_url: &str,
    handoff: serde_json::Value,
    request_timeout_secs: u64,
) -> LocalPocResult<serde_json::Value> {
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

struct LocalPocRecipient {
    address: String,
    coin_public_key: CoinPublicKey,
    encryption_public_key: encryption::PublicKey,
}

fn decode_local_recipient(env: &HashMap<String, String>) -> LocalPocResult<LocalPocRecipient> {
    let address = env_value(env, "MIDNIGHT_LOCAL_RECIPIENT_SHIELDED_ADDRESS");
    if address.trim().is_empty() {
        return Err("set MIDNIGHT_LOCAL_RECIPIENT_SHIELDED_ADDRESS for split-send e2e".into());
    }
    let network_id = env_value_or(env, "MIDNIGHT_LOCAL_NETWORK_ID", "undeployed");
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

    Ok(LocalPocRecipient {
        address: address.trim().to_string(),
        coin_public_key,
        encryption_public_key,
    })
}

async fn submit_split_send_transaction(
    env: &HashMap<String, String>,
    proof_server_url: &str,
    spend: &LocalPocWalletSpend,
    split_response: &serde_json::Value,
    recipient: &LocalPocRecipient,
    transfer_value: u128,
) -> LocalPocResult<serde_json::Value> {
    if env_value(env, "MIDNIGHT_LOCAL_RECOVERY_PHRASE")
        .trim()
        .is_empty()
    {
        return Err("set MIDNIGHT_LOCAL_RECOVERY_PHRASE for full split-send e2e submission".into());
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
        .well_formed_with_registry_policy(0, &AcceptAllRegistryRootPolicy)
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
        network_id: env_value_or(env, "MIDNIGHT_LOCAL_NETWORK_ID", "undeployed"),
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
        .arg(repo_root_tool("tools/local_balance_submit_split_tx.mjs")?)
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

fn local_transfer_amount(env: &HashMap<String, String>, coin_value: u128) -> LocalPocResult<u128> {
    let raw = env_value(env, "MIDNIGHT_LOCAL_TRANSFER_AMOUNT");
    let transfer_value = if raw.trim().is_empty() {
        DEFAULT_LOCAL_TRANSFER_AMOUNT
    } else {
        raw.trim().parse::<u128>().map_err(|e| {
            format!("MIDNIGHT_LOCAL_TRANSFER_AMOUNT must be a positive integer: {e}")
        })?
    };

    if transfer_value == 0 {
        return Err("MIDNIGHT_LOCAL_TRANSFER_AMOUNT must be greater than zero".into());
    }
    if transfer_value > coin_value {
        return Err(format!(
            "MIDNIGHT_LOCAL_TRANSFER_AMOUNT ({transfer_value}) exceeds selected shielded coin value ({coin_value})"
        )
        .into());
    }

    Ok(transfer_value)
}

async fn prove_zswap_output(
    output: &ZswapOutput<ProofPreimage, InMemoryDB>,
) -> LocalPocResult<ZswapOutput<Proof, InMemoryDB>> {
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

fn deserialize_tagged_hex<T: Deserializable + Tagged>(value: &str) -> LocalPocResult<T> {
    let bytes = hex::decode(value.trim().trim_start_matches("0x"))?;
    Ok(tagged_deserialize(&bytes[..])?)
}

fn deserialize_hex<T: Deserializable>(value: &str) -> LocalPocResult<T> {
    let bytes = hex::decode(value.trim().trim_start_matches("0x"))?;
    Ok(T::deserialize(&mut &bytes[..], 0)?)
}

pub fn local_poc_env() -> HashMap<String, String> {
    let mut values = HashMap::new();
    for (key, value) in std::env::vars() {
        if key.starts_with("MIDNIGHT_LOCAL_")
            || key.starts_with("MIDNIGHT_PREVIEW_")
            || key.starts_with("MIDNIGHT_PROOF_SERVER_")
        {
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

pub fn env_value(env: &HashMap<String, String>, key: &str) -> String {
    env.get(key)
        .cloned()
        .or_else(|| {
            key.strip_prefix("MIDNIGHT_LOCAL_")
                .and_then(|suffix| env.get(&format!("MIDNIGHT_PREVIEW_{suffix}")).cloned())
        })
        .unwrap_or_default()
}

pub(crate) fn env_value_or(env: &HashMap<String, String>, key: &str, default: &str) -> String {
    let value = env_value(env, key);
    if value.trim().is_empty() {
        default.to_string()
    } else {
        value
    }
}

fn fetch_local_zswap_events(
    env: &HashMap<String, String>,
    limit: usize,
) -> LocalPocResult<Vec<String>> {
    let endpoint = env_value(env, "MIDNIGHT_LOCAL_INDEXER_WS");
    let endpoint = if endpoint.trim().is_empty() {
        "ws://127.0.0.1:8088/api/v4/graphql/ws".to_string()
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
const timer = setTimeout(() => fail('timed out waiting for local zswap events'), 20000);
ws.addEventListener('open', () => {{
  ws.send(JSON.stringify({{ type: 'connection_init' }}));
}});
ws.addEventListener('message', (event) => {{
  const msg = JSON.parse(String(event.data));
  if (msg.type === 'connection_ack') {{
    ws.send(JSON.stringify({{
      id: 'local-zswap-events',
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
            "local indexer fetch failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    Ok(serde_json::from_slice(&output.stdout)?)
}

pub fn local_zswap_secret_keys_scan(
    env: &HashMap<String, String>,
) -> LocalPocResult<Vec<(usize, SecretKeys)>> {
    let scan_limit = env_value(env, "MIDNIGHT_LOCAL_ZSWAP_KEY_SCAN_LIMIT")
        .parse()
        .unwrap_or(1);
    (0..scan_limit)
        .map(|index| local_zswap_secret_keys(env, index).map(|key| (index, key)))
        .collect()
}

fn local_zswap_secret_keys(
    env: &HashMap<String, String>,
    index: usize,
) -> LocalPocResult<SecretKeys> {
    let seed_hex = env_value(env, "MIDNIGHT_LOCAL_ZSWAP_SEED_HEX");
    let seed_hex = if seed_hex.trim().is_empty() {
        derive_local_zswap_seed_hex(env, index)?
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
    spend: &LocalPocWalletSpend,
    coin_binding_tag: Fr,
    pk: CoinPublicKey,
    registration: &LocalPocWalletRegistration,
    witness: &LocalPocRegistryWitness,
) -> LocalPocResult<transient_crypto::proofs::Proof> {
    let preimage =
        build_client_derivation_preimage(spend, coin_binding_tag, pk, registration, witness);
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
    spend: &LocalPocWalletSpend,
    coin_binding_tag: Fr,
    pk: CoinPublicKey,
    registration: &LocalPocWalletRegistration,
    witness: &LocalPocRegistryWitness,
) -> ProofPreimage {
    // Solution A witness layout matches `circuits/sk_proof.compact` parameter
    // declaration order: (sk, pk, r, salt, coin, merkle_path).
    let mut inputs = Vec::new();
    spend.key.coin_secret_key.0.0.field_repr(&mut inputs); // sk - 2 Fr
    pk.0.0.field_repr(&mut inputs); // pk - 2 Fr
    inputs.push(registration.blinding); // r - 1 Fr
    inputs.push(registration.salt); // salt - 1 Fr
    spend.coin.nonce.0.0.field_repr(&mut inputs); // nonce - 2 Fr
    spend.coin.type_.0.0.field_repr(&mut inputs); // color - 2 Fr
    spend.coin.value.field_repr(&mut inputs); // value - 1 Fr
    witness.merkle_path.field_repr(&mut inputs); // leaf + 20 entries

    ProofPreimage {
        inputs,
        private_transcript: Vec::new(),
        public_transcript_inputs: client_derivation_public_transcript_inputs(
            spend.nullifier.0.0,
            coin_binding_tag,
            witness.registry_root.0,
        ),
        public_transcript_outputs: Vec::new(),
        binding_input: 0.into(),
        communications_commitment: None,
        key_location: KeyLocation(Cow::Borrowed(CLIENT_DERIVATION_KEY_LOCATION)),
    }
}

fn client_derivation_public_transcript_inputs(
    nullifier: [u8; 32],
    coin_binding_tag: Fr,
    registry_root: Fr,
) -> Vec<Fr> {
    // Mirrors `sk_proof.compact` ledger declaration order:
    //   cell 0: nullifier (Bytes<32>)
    //   cell 1: coinBindingTag (Field)
    //   cell 2: registryRoot (MerkleTreeDigest lowers to Field cell)
    let mut inputs = Vec::new();
    extend_ops(
        &mut inputs,
        Cell_write!([Key::Value(0u8.into())], false, [u8; 32], nullifier),
    );
    extend_ops(
        &mut inputs,
        Cell_write!([Key::Value(1u8.into())], false, Fr, coin_binding_tag),
    );
    extend_ops(
        &mut inputs,
        Cell_write!([Key::Value(2u8.into())], false, Fr, registry_root),
    );
    inputs
}

/// Solution A wallet registration produced once per local POC run. The Fr is
/// the in-circuit `regLeaf` value; the proof is off-chain evidence and is not
/// part of any split bundle.
#[derive(Debug, Clone)]
pub struct LocalPocWalletRegistration {
    pub blinding: Fr,
    pub salt: Fr,
    /// In-circuit `regLeaf` Field. Kept for diagnostics — the upgrade
    /// (`reg_leaf_bytes`) is what travels off-circuit.
    #[allow(dead_code)]
    pub reg_leaf_fr: Fr,
    pub reg_leaf_bytes: [u8; 32],
    /// Attestation proof generated during registration. Kept on the
    /// wallet as off-chain evidence; never bundled with split spends.
    #[allow(dead_code)]
    pub attestation_proof: Proof,
}

/// Single-leaf registry witness mirroring the synthetic first-registration
/// state for this wallet.
#[derive(Debug, Clone)]
pub(crate) struct LocalPocRegistryWitness {
    pub merkle_path: MerklePath<((), HashOutput)>,
    pub registry_root: MerkleTreeDigest,
}

fn build_first_registration_witness(
    registration: &LocalPocWalletRegistration,
) -> LocalPocResult<LocalPocRegistryWitness> {
    build_synthetic_witness(registration, /* add_dummy_sibling = */ false)
}

/// Phase 4 negative-control witness: places the real `reg_leaf` at index 0
/// AND a dummy `[0xDE; 32]` leaf at index 1 so the resulting root is one the
/// chain never registered (it is not in the registry's historic-roots set).
/// The proof itself is fully valid (path/leaf/root are self-consistent),
/// so the wallet → proof-server roundtrip succeeds — but ledger admission
/// will reject the bundle with `SplitRegistryRootNotRecognized`, proving the
/// `MIDNIGHT_SPLIT_REGISTRY_DEV_ACCEPT_ALL=1` bypass is actually off.
fn build_corrupt_registration_witness(
    registration: &LocalPocWalletRegistration,
) -> LocalPocResult<LocalPocRegistryWitness> {
    build_synthetic_witness(registration, /* add_dummy_sibling = */ true)
}

fn build_synthetic_witness(
    registration: &LocalPocWalletRegistration,
    add_dummy_sibling: bool,
) -> LocalPocResult<LocalPocRegistryWitness> {
    let leaf_hash = HashOutput(registration.reg_leaf_bytes);
    let mut mt = MerkleTree::<(), InMemoryDB>::blank(REGISTRY_TREE_HEIGHT)
        .update_hash(0, leaf_hash, ());
    if add_dummy_sibling {
        // Domain-separated dummy that no honest wallet would ever register.
        let dummy = HashOutput(*b"midnight:split-prove:dummy-sib-1");
        mt = mt.update_hash(1, dummy, ());
    }
    let mt = mt.rehash();
    let merkle_path = mt
        .path_for_leaf(0, ((), leaf_hash))
        .map_err(|e| format!("registry path_for_leaf failed: {e}"))?;
    // Apply `merkleTreePathRootNoLeafHash` semantics (no extra leaf-hash).
    let registry_root = MerkleTreeDigest(merkle_path.path.iter().fold(
        degrade_to_transient(leaf_hash),
        |acc, entry| {
            if entry.goes_left {
                transient_hash(&[acc, entry.sibling.0])
            } else {
                transient_hash(&[entry.sibling.0, acc])
            }
        },
    ));
    if add_dummy_sibling {
        tracing::info!(
            registry_root = %hex::encode(registry_root.0.as_le_bytes()),
            leaf = %hex::encode(registration.reg_leaf_bytes),
            first_sibling = %hex::encode(merkle_path.path[0].sibling.0.as_le_bytes()),
            "built CORRUPTED synthetic registration witness (Phase 4 negative control)"
        );
    }
    Ok(LocalPocRegistryWitness {
        merkle_path,
        registry_root,
    })
}

fn derive_reg_leaf(sk: &coin_structure::coin::SecretKey, r: Fr, salt: Fr) -> (Fr, Fr) {
    let mut sk_limbs = Vec::new();
    sk.0.0.field_repr(&mut sk_limbs);
    debug_assert_eq!(sk_limbs.len(), 2, "Bytes<32> must produce 2 Fr limbs");
    let sep_sk = ascii_to_fr_le(SK_COMMIT_SEPARATOR);
    let c_sk_fr = transient_hash(&[sep_sk, sk_limbs[0], sk_limbs[1], r]);
    let sep_reg = ascii_to_fr_le(REG_LEAF_SEPARATOR);
    let reg_leaf_fr = transient_hash(&[sep_reg, c_sk_fr, salt]);
    (c_sk_fr, reg_leaf_fr)
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
    salt: Fr,
    reg_leaf_fr: Fr,
) -> ProofPreimage {
    let mut inputs = Vec::new();
    sk.0.0.field_repr(&mut inputs);
    inputs.push(r);
    inputs.push(salt);
    ProofPreimage {
        inputs,
        private_transcript: Vec::new(),
        public_transcript_inputs: wallet_attestation_public_transcript_inputs(reg_leaf_fr),
        public_transcript_outputs: Vec::new(),
        binding_input: 0.into(),
        communications_commitment: None,
        key_location: KeyLocation(Cow::Borrowed(WALLET_ATTESTATION_KEY_LOCATION)),
    }
}

fn wallet_attestation_public_transcript_inputs(reg_leaf_fr: Fr) -> Vec<Fr> {
    let mut inputs = Vec::new();
    extend_ops(
        &mut inputs,
        Cell_write!([Key::Value(0u8.into())], false, Fr, reg_leaf_fr),
    );
    inputs
}

/// Derive the wallet's `(r, salt)` blinding pair via Poseidon over the
/// coin secret key. POC fallback used by the synthetic integration tests
/// (and any caller that doesn't have a BIP39 recovery phrase available):
/// same `sk` → same `(r, salt)` → same `reg_leaf`, but without the
/// production-shaped HKDF-from-master-seed flow. Production callers go
/// through [`derive_blinding_pair_from_bip39`] instead.
fn derive_blinding_pair_from_sk(sk: &coin_structure::coin::SecretKey) -> (Fr, Fr) {
    let mut sk_limbs = Vec::new();
    sk.0.0.field_repr(&mut sk_limbs);
    debug_assert_eq!(sk_limbs.len(), 2, "Bytes<32> must produce 2 Fr limbs");
    let r = transient_hash(&[
        ascii_to_fr_le(SK_R_DERIVE_SEPARATOR),
        sk_limbs[0],
        sk_limbs[1],
    ]);
    let salt = transient_hash(&[
        ascii_to_fr_le(SK_SALT_DERIVE_SEPARATOR),
        sk_limbs[0],
        sk_limbs[1],
    ]);
    (r, salt)
}

/// Production-shaped derivation: HKDF-SHA256 over the BIP39 seed with a
/// stable domain separator and the wallet's `(account, key_index)`
/// identifier. Output is two 64-byte uniform chunks, each fed to
/// [`Fr::from_uniform_bytes`] for unbiased reduction into the Jubjub
/// scalar field. Shells out to [`tools/derive_midnight_wallet_blinding.mjs`]
/// the same way the zswap-seed derivation does.
///
/// Returns an error if `MIDNIGHT_LOCAL_RECOVERY_PHRASE` isn't set —
/// callers must fall back to [`derive_blinding_pair_from_sk`] for
/// chainless/test paths.
fn derive_blinding_pair_from_bip39(
    env: &HashMap<String, String>,
    key_index: usize,
) -> LocalPocResult<(Fr, Fr)> {
    let phrase = env_value(env, "MIDNIGHT_LOCAL_RECOVERY_PHRASE");
    if phrase.trim().is_empty() {
        return Err(
            "derive_blinding_pair_from_bip39: MIDNIGHT_LOCAL_RECOVERY_PHRASE not set in env".into(),
        );
    }

    let output = Command::new("node")
        .arg(repo_root_tool("tools/derive_midnight_wallet_blinding.mjs")?)
        .env("MIDNIGHT_LOCAL_RECOVERY_PHRASE", phrase)
        .env(
            "MIDNIGHT_LOCAL_ACCOUNT",
            env_value(env, "MIDNIGHT_LOCAL_ACCOUNT"),
        )
        .env("MIDNIGHT_LOCAL_ZSWAP_KEY_INDEX", key_index.to_string())
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "wallet-blinding derivation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let r_hex = json
        .get("rUniformHex")
        .and_then(|v| v.as_str())
        .ok_or("blinding helper missing rUniformHex")?;
    let salt_hex = json
        .get("saltUniformHex")
        .and_then(|v| v.as_str())
        .ok_or("blinding helper missing saltUniformHex")?;

    let r_bytes: [u8; 64] = hex::decode(r_hex)?
        .try_into()
        .map_err(|v: Vec<u8>| format!("rUniformHex must be 64 bytes, got {}", v.len()))?;
    let salt_bytes: [u8; 64] = hex::decode(salt_hex)?
        .try_into()
        .map_err(|v: Vec<u8>| format!("saltUniformHex must be 64 bytes, got {}", v.len()))?;

    Ok((
        Fr::from_uniform_bytes(&r_bytes),
        Fr::from_uniform_bytes(&salt_bytes),
    ))
}

/// Generate the per-wallet registration.
///
/// When a BIP39 recovery phrase is available in `env`, `(r, salt)` are
/// derived via HKDF-SHA256 over the BIP39 seed (production-shaped). When
/// no recovery phrase is present, falls back to a Poseidon-over-sk
/// derivation — the synthetic integration tests rely on this so they can
/// run with `StdRng`-seeded synthetic keys and no `.env`. Both paths are
/// seed-stable: same wallet → same `reg_leaf` across the `register-wallet`
/// run and every subsequent split spend.
pub async fn prove_wallet_attestation(
    sk: &coin_structure::coin::SecretKey,
    env: &HashMap<String, String>,
    key_index: usize,
) -> LocalPocResult<LocalPocWalletRegistration> {
    let (r, salt) = if env_value(env, "MIDNIGHT_LOCAL_RECOVERY_PHRASE")
        .trim()
        .is_empty()
    {
        derive_blinding_pair_from_sk(sk)
    } else {
        derive_blinding_pair_from_bip39(env, key_index)?
    };
    let (_c_sk_fr, reg_leaf_fr) = derive_reg_leaf(sk, r, salt);
    let reg_leaf_bytes = upgrade_from_transient(reg_leaf_fr).0;

    let preimage = build_wallet_attestation_preimage(sk, r, salt, reg_leaf_fr);
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
    Ok(LocalPocWalletRegistration {
        blinding: r,
        salt,
        reg_leaf_fr,
        reg_leaf_bytes,
        attestation_proof: proof,
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

pub(crate) struct ClientDerivationResolver<P> {
    params_and_fallback: P,
}

impl<P> ClientDerivationResolver<P> {
    pub(crate) fn new(params_and_fallback: P) -> Self {
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
        } else if key.0.as_ref() == REGISTER_KEY_LOCATION {
            Ok(Some(register_proving_data()))
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

/// Proving-key material for the wallet_registry `register(leaf)` circuit.
/// Compact's static layout puts the compiled keys under `keys/register.*`,
/// which the build pipeline copies to `circuits/static/wallet-registry/`.
fn register_proving_data() -> ProvingKeyMaterial {
    ProvingKeyMaterial {
        prover_key: include_bytes!("../../../../circuits/static/wallet-registry/register.prover")
            .to_vec(),
        verifier_key: include_bytes!(
            "../../../../circuits/static/wallet-registry/register.verifier"
        )
        .to_vec(),
        ir_source: include_bytes!("../../../../circuits/static/wallet-registry/register.bzkir")
            .to_vec(),
    }
}

fn derive_local_zswap_seed_hex(
    env: &HashMap<String, String>,
    index: usize,
) -> LocalPocResult<String> {
    let phrase = env_value(env, "MIDNIGHT_LOCAL_RECOVERY_PHRASE");
    if phrase.trim().is_empty() {
        return Err(
            "set MIDNIGHT_LOCAL_RECOVERY_PHRASE or MIDNIGHT_LOCAL_ZSWAP_SEED_HEX in .env".into(),
        );
    }

    let output = Command::new("node")
        .arg(repo_root_tool("tools/derive_midnight_zswap_seed.mjs")?)
        .env("MIDNIGHT_LOCAL_RECOVERY_PHRASE", phrase)
        .env(
            "MIDNIGHT_LOCAL_ACCOUNT",
            env_value(env, "MIDNIGHT_LOCAL_ACCOUNT"),
        )
        .env("MIDNIGHT_LOCAL_ZSWAP_KEY_INDEX", index.to_string())
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

pub fn repo_root_tool(relative_path: &str) -> LocalPocResult<PathBuf> {
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
