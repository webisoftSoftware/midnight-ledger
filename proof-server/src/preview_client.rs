// This file is part of midnight-ledger.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: Apache-2.0

use base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};
use coin_structure::coin::{Commitment, Info as CoinInfo, Nullifier, PublicKey as CoinPublicKey};
use coin_structure::transfer::SenderEvidence;
use ledger::events::{Event, EventDetails};
use onchain_runtime::ops::{Key, Op};
use onchain_runtime::program_fragments::Cell_write;
use onchain_runtime::result_mode::ResultModeVerify;
use onchain_runtime::state::StateValue;
use rand::Rng;
use rand::rngs::OsRng;
use serde_json::json;
use serialize::{tagged_deserialize, tagged_serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use storage::arena::Sp;
use storage::db::InMemoryDB;
use transient_crypto::curve::Fr;
use transient_crypto::hash::transient_hash;
use transient_crypto::proofs::{
    KeyLocation, ParamsProver, ParamsProverProvider, ProofPreimage, ProvingKeyMaterial, Resolver,
};
use transient_crypto::repr::FieldRepr;
use zswap::keys::{SecretKeys, Seed};
use zswap::ledger::State as ZswapLedgerState;
use zswap::prove::ZswapResolver;

pub type PreviewResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const CLIENT_DERIVATION_KEY_LOCATION: &str = "split/client/sk-derivation";

pub struct PreviewSplitProveOptions<'a> {
    pub proof_server_url: &'a str,
    pub event_limit: Option<usize>,
    pub request_timeout_secs: u64,
}

#[derive(Debug)]
pub struct PreviewSplitProveReport {
    pub key_index: usize,
    pub mt_index: u64,
    pub coin_value: String,
    pub token_type_hex: String,
    pub status: String,
    pub proof_hex_len: usize,
    pub response: serde_json::Value,
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
    let wallet_spend = select_preview_wallet_spend(&secret_keys, &env, event_limit)?;
    let handoff = build_split_spend_handoff(&wallet_spend).await?;
    let body = post_split_spend_handoff(
        options.proof_server_url,
        handoff,
        options.request_timeout_secs,
    )
    .await?;

    let proof_hex_len = body["proofHex"].as_str().map(str::len).unwrap_or_default();
    Ok(PreviewSplitProveReport {
        key_index: wallet_spend.key_index,
        mt_index: wallet_spend.mt_index,
        coin_value: wallet_spend.coin.value.to_string(),
        token_type_hex: hex::encode(wallet_spend.coin.type_.0.0),
        status: body["status"].as_str().unwrap_or_default().to_string(),
        proof_hex_len,
        response: body,
    })
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
                    let nullifier =
                        coin.nullifier(&SenderEvidence::User(Cow::Borrowed(&key.coin_secret_key)));
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
    let mut zswap_state_bytes = Vec::new();
    tagged_serialize(&spend.zswap_state, &mut zswap_state_bytes)?;
    let sk_blinding = OsRng.r#gen();
    let sk_commitment = split_sk_commitment(&spend.key, sk_blinding);
    let pk = spend.key.coin_secret_key.public_key();
    let client_derivation_proof =
        prove_client_derivation(spend, sk_blinding, sk_commitment, pk).await?;

    Ok(json!({
        "skCommitment": hex::encode(sk_commitment.0.to_bytes_le()),
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
    }))
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

fn split_sk_commitment(key: &SecretKeys, sk_blinding: Fr) -> Fr {
    let mut sk_fields = Vec::new();
    key.coin_secret_key.0.0.field_repr(&mut sk_fields);
    transient_hash(&[sk_fields[0], sk_fields[1], sk_blinding])
}

async fn prove_client_derivation(
    spend: &PreviewWalletSpend,
    sk_blinding: Fr,
    sk_commitment: Fr,
    pk: CoinPublicKey,
) -> PreviewResult<transient_crypto::proofs::Proof> {
    let preimage = build_client_derivation_preimage(spend, sk_blinding, sk_commitment, pk);
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
    sk_blinding: Fr,
    sk_commitment: Fr,
    pk: CoinPublicKey,
) -> ProofPreimage {
    let mut inputs = Vec::new();
    spend.key.coin_secret_key.0.0.field_repr(&mut inputs);
    inputs.push(sk_blinding);
    spend.coin.nonce.0.0.field_repr(&mut inputs);
    spend.coin.type_.0.0.field_repr(&mut inputs);
    spend.coin.value.field_repr(&mut inputs);

    ProofPreimage {
        inputs,
        private_transcript: Vec::new(),
        public_transcript_inputs: client_derivation_public_transcript_inputs(
            sk_commitment,
            pk,
            spend.commitment.0.0,
            spend.nullifier.0.0,
        ),
        public_transcript_outputs: Vec::new(),
        binding_input: 0.into(),
        communications_commitment: None,
        key_location: KeyLocation(Cow::Borrowed(CLIENT_DERIVATION_KEY_LOCATION)),
    }
}

fn client_derivation_public_transcript_inputs(
    sk_commitment: Fr,
    pk: CoinPublicKey,
    commitment_hash: [u8; 32],
    nullifier: [u8; 32],
) -> Vec<Fr> {
    let mut inputs = Vec::new();
    extend_ops(
        &mut inputs,
        Cell_write!([Key::Value(0u8.into())], false, Fr, sk_commitment),
    );
    extend_ops(
        &mut inputs,
        Cell_write!([Key::Value(1u8.into())], false, CoinPublicKey, pk),
    );
    extend_ops(
        &mut inputs,
        Cell_write!([Key::Value(2u8.into())], false, [u8; 32], commitment_hash),
    );
    extend_ops(
        &mut inputs,
        Cell_write!([Key::Value(3u8.into())], false, [u8; 32], nullifier),
    );
    inputs
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
