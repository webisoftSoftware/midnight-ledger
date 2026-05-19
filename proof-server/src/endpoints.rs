// This file is part of midnight-ledger.
// Copyright (C) 2025 Midnight Foundation
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![deny(unreachable_pub)]
#![deny(warnings)]
use actix_web::error::ErrorBadRequest;
use actix_web::http::StatusCode;
use actix_web::web::{self, Bytes, BytesMut, Data, Payload};
use actix_web::{Error, HttpResponse, HttpResponseBuilder, Responder, get, post};
use base_crypto::data_provider::{self, MidnightDataProvider};
use base_crypto::data_provider::{FetchMode, OutputMode};
use base_crypto::hash::HashOutput;
use base_crypto::signatures::Signature;
use coin_structure::coin::{
    Commitment, Info as CoinInfo, Nullifier, PublicKey as CoinPublicKey,
    QualifiedInfo as QualifiedCoinInfo, ShieldedTokenType,
};
use coin_structure::contract::ContractAddress;
use coin_structure::transfer::Recipient;
use futures_util::stream::StreamExt;
use hex::ToHex;
use introspection::Introspection;
use lazy_static::lazy_static;
use ledger::dust::DustResolver;
use ledger::prove::Resolver;
use ledger::structure::{
    INITIAL_TRANSACTION_COST_MODEL, ProofPreimageMarker, ProofPreimageVersioned, ProofVersioned,
    Transaction,
};
use onchain_runtime::ops::{Key, Op};
use onchain_runtime::program_fragments::Cell_write;
use onchain_runtime::result_mode::ResultModeVerify;
use onchain_runtime::state::StateValue;
use rand::rngs::OsRng;
use serialize::{tagged_deserialize, tagged_serialize};
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::time::Instant;
use storage::arena::Sp;
use storage::db::InMemoryDB;
use tracing::{debug, info};
use transient_crypto::commitment::PedersenRandomness;
use transient_crypto::curve::Fr;
use transient_crypto::proofs::{
    KeyLocation, PARAMS_VERIFIER, ParamsProverProvider, Proof, ProvingKeyMaterial,
    Resolver as ResolverT, VerifierKey, WrappedIr,
};
use transient_crypto::repr::FieldRepr;

use zkir as zkir_v2;
use zswap::error::MalformedOffer;
use zswap::ledger::State as ZswapLedgerState;
use zswap::prove::ZswapResolver;
use zswap::split_coin_binding_tag;
use zswap::split_wrapper::{
    SPLIT_WRAPPER_K, SplitWrapperProvingKey, SplitWrapperWitness, prove_split_wrapper,
    read_split_wrapper_proving_key, split_wrapper_inner_keys,
};
use zswap::verify::{CLIENT_DERIVATION_VK, SPEND_SPLIT_VK, WALLET_ATTESTATION_VK};
use zswap::{Input, ZswapInputProof};

use crate::versioned_ir;
use crate::worker_pool::{JobStatus, WorkError, WorkerPool};

lazy_static! {
    pub static ref PUBLIC_PARAMS: ZswapResolver = ZswapResolver(
        MidnightDataProvider::new(
            data_provider::FetchMode::OnDemand,
            data_provider::OutputMode::Log,
            zswap::ZSWAP_EXPECTED_FILES.to_vec(),
        )
        .expect("data provider initialization failed")
    );
    static ref SPLIT_WRAPPER_PROVING_KEY: Result<Arc<SplitWrapperProvingKey>, String> = {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../zswap/static/spend-split-wrapper.prover");
        fs::read(&path)
            .map_err(|e| format!("read split wrapper prover key {}: {e}", path.display()))
            .and_then(|bytes| {
                read_split_wrapper_proving_key(&bytes)
                    .map(Arc::new)
                    .map_err(|e| format!("deserialize split wrapper prover key: {e}"))
            })
    };
}

async fn payload_to_bytes(mut payload: Payload) -> Result<Bytes, Error> {
    let mut body = BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk?;
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

fn split_wrapper_proving_key() -> Result<Arc<SplitWrapperProvingKey>, WorkError> {
    match &*SPLIT_WRAPPER_PROVING_KEY {
        Ok(key) => Ok(key.clone()),
        Err(message) => Err(WorkError::InternalError(message.clone())),
    }
}

type TransactionProvePayload<S> = (
    Transaction<S, ProofPreimageMarker, PedersenRandomness, InMemoryDB>,
    HashMap<String, ProvingKeyMaterial>,
);

#[get("/version")]
pub(crate) async fn version() -> impl Responder {
    env!("CARGO_PKG_VERSION")
}

#[get("/fetch-params/{k}")]
pub(crate) async fn fetch_k(path: web::Path<u8>) -> impl Responder {
    let k = path.into_inner();
    if !(0..=25).contains(&k) {
        return Err(ErrorBadRequest(format!("k={k} out of range")));
    }
    PUBLIC_PARAMS.0.fetch_k(k).await?;
    Ok("success")
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HealthResponse {
    status: &'static str,
    timestamp: time::OffsetDateTime,
}

pub(crate) async fn health() -> Result<web::Json<HealthResponse>, Error> {
    let status = HealthResponse {
        status: "ok",
        timestamp: time::OffsetDateTime::now_utc(),
    };
    Ok(web::Json(status))
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SplitSpendRequest {
    coin_binding_tag: String,
    nullifier: String,
    pk: String,
    commitment_hash: String,
    coin_value: u128,
    coin_type: Option<String>,
    coin_nonce: String,
    mt_index: u64,
    contract_address: Option<String>,
    zswap_state: Option<String>,
    zswap_state_file: Option<String>,
    prove: Option<bool>,
    client_derivation_proof: Option<String>,
    /// v3: hex Fr (little-endian 32 bytes) — Poseidon commitment to sk from
    /// the wallet attestation.
    #[serde(default)]
    attested_commitment_sk: Option<String>,
    /// v3: hex-encoded wallet attestation proof. Required for v3 split spends.
    #[serde(default)]
    attestation_proof: Option<String>,
    proving_data: Option<SplitProvingData>,
}

#[derive(Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SplitProvingData {
    prover_key: String,
    verifier_key: String,
    ir_source: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SplitSpendResponse {
    status: SplitSpendStatus,
    key_location: String,
    inputs_count: usize,
    public_transcript_inputs_count: usize,
    first_input: String,
    raw_secret_key_present: bool,
    merkle_path_source: SplitMerklePathSource,
    preimage_hex: String,
    input_preimage_hex: String,
    proof_hex: Option<String>,
    proved_input_hex: Option<String>,
    proof_version: Option<String>,
    proof_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    server_client_deriv_verify_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    server_split_prove_ms: Option<u128>,
    server_total_ms: u128,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum SplitMerklePathSource {
    ZswapState,
    ZswapStateFile,
    SimulatedSingleLeaf,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum SplitSpendStatus {
    PreimageBuilt,
    ProofBuilt,
    ProofUnavailable,
}

#[post("/v2/prove-split-spend")]
pub(crate) async fn prove_split_spend(
    pool: Data<Arc<WorkerPool>>,
    request: web::Json<SplitSpendRequest>,
) -> Result<web::Json<SplitSpendResponse>, Error> {
    info!("Starting to process request for /v2/prove-split-spend...");
    let server_t0 = Instant::now();

    let coin_binding_tag = fr_from_hex(&request.coin_binding_tag)?;
    let nullifier = Nullifier(HashOutput(bytes32_from_hex(&request.nullifier)?));
    let pk = CoinPublicKey(HashOutput(bytes32_from_hex(&request.pk)?));
    let commitment_hash = Commitment(HashOutput(bytes32_from_hex(&request.commitment_hash)?));
    let nonce = coin_structure::coin::Nonce(HashOutput(bytes32_from_hex(&request.coin_nonce)?));
    let contract_address = request
        .contract_address
        .as_deref()
        .map(bytes32_from_hex)
        .transpose()?
        .map(|bytes| ContractAddress(HashOutput(bytes)));

    let coin = QualifiedCoinInfo {
        value: request.coin_value.into(),
        type_: request
            .coin_type
            .as_deref()
            .map(bytes32_from_hex)
            .transpose()?
            .map(|bytes| ShieldedTokenType(HashOutput(bytes)))
            .unwrap_or_default(),
        nonce,
        mt_index: request.mt_index,
    };
    if contract_address.is_some() {
        return Err(ErrorBadRequest(
            "split spend proof requests currently require user-owned coins",
        ));
    }
    let coin_info = CoinInfo::from(&coin);
    let expected_commitment = coin_info.commitment(&Recipient::User(pk));
    if expected_commitment != commitment_hash {
        return Err(ErrorBadRequest(
            "commitmentHash does not match coin metadata and pk",
        ));
    }
    let expected_coin_binding_tag = split_coin_binding_tag(&coin_info, pk);
    if expected_coin_binding_tag != coin_binding_tag {
        return Err(ErrorBadRequest(
            "coinBindingTag does not match coin metadata and pk",
        ));
    }
    let (tree, merkle_path_source) = split_spend_tree(&request, commitment_hash)?;
    if request.prove.unwrap_or(false)
        && matches!(
            &merkle_path_source,
            SplitMerklePathSource::SimulatedSingleLeaf
        )
    {
        return Err(ErrorBadRequest(
            "split spend proof requests must include zswapState or zswapStateFile",
        ));
    }
    // v3: parse the Poseidon `C_sk` and the bundled wallet attestation. Both
    // are required for split spends under the v3 envelope. Pre-verify the
    // attestation before doing any client-derivation prover work so a bad
    // attestation fails fast.
    let commitment_sk = request
        .attested_commitment_sk
        .as_deref()
        .map(fr_from_hex)
        .transpose()?
        .ok_or_else(|| {
            ErrorBadRequest("attestedCommitmentSk is required for split spend proof requests (v3)")
        })?;
    let attestation_proof_hex = request.attestation_proof.as_deref().ok_or_else(|| {
        ErrorBadRequest("attestationProof is required for split spend proof requests (v3)")
    })?;
    info!(
        stage = "verify-wallet-attestation",
        role = "server",
        "▶ SERVER/verify-wallet-attestation"
    );
    verify_attestation_proof(attestation_proof_hex, pk, commitment_sk).await?;
    info!(
        stage = "verify-wallet-attestation",
        role = "server",
        "✓ SERVER/verify-wallet-attestation"
    );
    info!(
        stage = "verify-client-derivation",
        role = "server",
        "▶ SERVER/verify-client-derivation"
    );
    let verify_start = Instant::now();
    verify_client_derivation_proof(&request, pk, nullifier, coin_binding_tag, commitment_sk)
        .await?;
    let elapsed = verify_start.elapsed().as_millis();
    let server_client_deriv_verify_ms = Some(elapsed);
    info!(
        stage = "verify-client-derivation",
        role = "server",
        elapsed_ms = elapsed as u64,
        "✓ SERVER/verify-client-derivation"
    );
    let client_derivation_proof = request
        .client_derivation_proof
        .as_deref()
        .map(bytes_from_hex)
        .transpose()?
        .map(Proof)
        .ok_or_else(|| ErrorBadRequest(MalformedOffer::MissingClientDerivationProof.to_string()))?;
    let attestation_proof = Proof(bytes_from_hex(attestation_proof_hex)?);

    let split_input = Input::new_split(
        &mut OsRng,
        &coin,
        None,
        nullifier,
        commitment_hash,
        pk,
        coin_binding_tag,
        commitment_sk,
        client_derivation_proof,
        attestation_proof,
        contract_address,
        &tree,
    )
    .map_err(|e| ErrorBadRequest(format!("build split spend preimage: {e:?}")))?;
    let input = &split_input.input;

    let first_input = input
        .proof
        .inputs
        .first()
        .ok_or_else(|| ErrorBadRequest("split spend preimage had no inputs"))?;

    let versioned_preimage = ProofPreimageVersioned::V2(input.proof.clone());
    let mut preimage_bytes = Vec::new();
    tagged_serialize(&versioned_preimage, &mut preimage_bytes)
        .map_err(|e| ErrorBadRequest(format!("serialize split spend preimage: {e}")))?;
    let mut input_preimage_bytes = Vec::new();
    tagged_serialize(&input, &mut input_preimage_bytes)
        .map_err(|e| ErrorBadRequest(format!("serialize split spend input preimage: {e}")))?;

    let mut server_split_prove_ms: Option<u128> = None;
    let (proof_hex, proved_input_hex, proof_version, proof_error) = if request
        .prove
        .unwrap_or(false)
    {
        info!(
            stage = "split-prove",
            role = "server",
            "▶ SERVER/split-prove"
        );
        let prove_start = Instant::now();
        let ppi = input.proof.clone();
        let split_input_for_worker = split_input.clone();
        let inline_data = request
            .proving_data
            .clone()
            .map(TryInto::try_into)
            .transpose()?;
        let (_id, updates) = pool
            .submit_and_subscribe(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async move {
                    let inline_data_resolver = inline_data.clone();
                    let resolver = Resolver::new(
                        PUBLIC_PARAMS.clone(),
                        DustResolver(
                            MidnightDataProvider::new(
                                FetchMode::OnDemand,
                                OutputMode::Log,
                                ledger::dust::DUST_EXPECTED_FILES.to_owned(),
                            )
                            .expect("data provider initialization failed"),
                        ),
                        Box::new(move |_: KeyLocation| {
                            Box::pin(std::future::ready(Ok(inline_data_resolver.clone())))
                        }),
                    );
                    let (spend_proof, _) =
                        zkir_v2::prove_poseidon(&ppi, OsRng, &resolver, &resolver)
                            .await
                            .map_err(|e| WorkError::BadInput(e.to_string()))?;
                    let v3_proved_input = split_input_for_worker.into_proved_input(spend_proof);
                    let split_bundle = match ZswapInputProof::decode(&v3_proved_input.proof)
                        .map_err(|_| {
                            WorkError::InternalError(
                                "generated split proof did not decode as v3 bundle".to_string(),
                            )
                        })? {
                        ZswapInputProof::Split(bundle) => bundle,
                        ZswapInputProof::Plain(_) | ZswapInputProof::SplitWrapped(_) => {
                            return Err(WorkError::InternalError(
                                "generated split proof had unexpected envelope".to_string(),
                            ));
                        }
                    };
                    let witness =
                        SplitWrapperWitness::from_split_bundle(&v3_proved_input, 0, &split_bundle)
                            .map_err(|e| WorkError::InternalError(e.to_string()))?;
                    let wrapper_params = resolver
                        .get_params(SPLIT_WRAPPER_K)
                        .await
                        .map_err(|e| WorkError::InternalError(e.to_string()))?;
                    let wrapper_proving_key = split_wrapper_proving_key()?;
                    let inner_keys = split_wrapper_inner_keys(
                        &WALLET_ATTESTATION_VK,
                        &CLIENT_DERIVATION_VK,
                        &SPEND_SPLIT_VK,
                    )
                    .map_err(|e| WorkError::InternalError(e.to_string()))?;
                    let wrapper_bundle = prove_split_wrapper(
                        &wrapper_params,
                        &PARAMS_VERIFIER,
                        &wrapper_proving_key,
                        &inner_keys,
                        &witness,
                        OsRng,
                    )
                    .map_err(|e| WorkError::BadInput(e.to_string()))?;
                    let proof = ZswapInputProof::SplitWrapped(wrapper_bundle).encode();

                    let mut response = Vec::new();
                    tagged_serialize(&ProofVersioned::V2(proof), &mut response)
                        .map_err(|e| WorkError::InternalError(e.to_string()))?;
                    Ok(response)
                })
            })
            .await?;
        let outcome = match JobStatus::wait_for_success(&updates).await {
            Ok(bytes) => {
                let proof_versioned: ProofVersioned = tagged_deserialize(&bytes[..])
                    .map_err(|e| ErrorBadRequest(format!("deserialize split spend proof: {e}")))?;
                let proof = match proof_versioned {
                    ProofVersioned::V2(proof) => proof,
                    _ => {
                        return Err(ErrorBadRequest(
                            "expected split spend proof[v2], got a different version",
                        ));
                    }
                };
                let proved_input = Input {
                    nullifier: split_input.input.nullifier,
                    value_commitment: split_input.input.value_commitment,
                    contract_address: split_input.input.contract_address.clone(),
                    merkle_tree_root: split_input.input.merkle_tree_root,
                    proof: Arc::new(proof),
                };
                let proof = (*proved_input.proof).clone();
                let mut proof_bytes = Vec::new();
                tagged_serialize(&ProofVersioned::V2(proof), &mut proof_bytes)
                    .map_err(|e| ErrorBadRequest(format!("serialize bundled proof: {e}")))?;
                let mut proved_input_bytes = Vec::new();
                tagged_serialize(&proved_input, &mut proved_input_bytes).map_err(|e| {
                    ErrorBadRequest(format!("serialize proved split spend input: {e}"))
                })?;
                (
                    Some(proof_bytes.encode_hex()),
                    Some(proved_input_bytes.encode_hex()),
                    Some("split-wrapper-v4".to_string()),
                    None,
                )
            }
            Err(e) => (None, None, None, Some(work_error_message(e))),
        };
        let elapsed = prove_start.elapsed().as_millis();
        server_split_prove_ms = Some(elapsed);
        info!(
            stage = "split-prove",
            role = "server",
            elapsed_ms = elapsed as u64,
            "✓ SERVER/split-prove"
        );
        outcome
    } else {
        (None, None, None, None)
    };
    let status = match (&proof_hex, &proof_error, request.prove.unwrap_or(false)) {
        (Some(_), None, _) => SplitSpendStatus::ProofBuilt,
        (None, Some(_), _) => SplitSpendStatus::ProofUnavailable,
        _ => SplitSpendStatus::PreimageBuilt,
    };

    Ok(web::Json(SplitSpendResponse {
        status,
        key_location: input.proof.key_location.0.to_string(),
        inputs_count: input.proof.inputs.len(),
        public_transcript_inputs_count: input.proof.public_transcript_inputs.len(),
        first_input: first_input.0.to_bytes_le().encode_hex(),
        raw_secret_key_present: false,
        merkle_path_source,
        preimage_hex: preimage_bytes.encode_hex(),
        input_preimage_hex: input_preimage_bytes.encode_hex(),
        proof_hex,
        proved_input_hex,
        proof_version,
        proof_error,
        server_client_deriv_verify_ms,
        server_split_prove_ms,
        server_total_ms: server_t0.elapsed().as_millis(),
    }))
}

fn split_spend_tree(
    request: &SplitSpendRequest,
    commitment_hash: Commitment,
) -> Result<
    (
        transient_crypto::merkle_tree::MerkleTree<
            Option<storage::arena::Sp<ContractAddress, InMemoryDB>>,
            InMemoryDB,
        >,
        SplitMerklePathSource,
    ),
    Error,
> {
    if let Some(zswap_state) = &request.zswap_state {
        return Ok((
            zswap_state_from_hex(zswap_state)?.coin_coms.rehash(),
            SplitMerklePathSource::ZswapState,
        ));
    }

    let zswap_state_file = request
        .zswap_state_file
        .clone()
        .or_else(|| std::env::var("MIDNIGHT_PROOF_SERVER_ZSWAP_STATE_FILE").ok());
    if let Some(path) = zswap_state_file {
        let zswap_state = fs::read_to_string(path)
            .map_err(|e| ErrorBadRequest(format!("read zswap state file: {e}")))?;
        return Ok((
            zswap_state_from_hex(zswap_state.trim())?.coin_coms.rehash(),
            SplitMerklePathSource::ZswapStateFile,
        ));
    }

    let tree = transient_crypto::merkle_tree::MerkleTree::blank(zswap::ZSWAP_TREE_HEIGHT)
        .update_hash(request.mt_index, commitment_hash.0, None)
        .rehash();
    Ok((tree, SplitMerklePathSource::SimulatedSingleLeaf))
}

fn zswap_state_from_hex(value: &str) -> Result<ZswapLedgerState<InMemoryDB>, Error> {
    let bytes = bytes_from_hex(value)?;
    tagged_deserialize(&bytes[..])
        .map_err(|e| ErrorBadRequest(format!("deserialize zswap state: {e}")))
}

async fn verify_client_derivation_proof(
    request: &SplitSpendRequest,
    pk: CoinPublicKey,
    nullifier: Nullifier,
    coin_binding_tag: Fr,
    commitment_sk: Fr,
) -> Result<(), Error> {
    let proof_hex = request.client_derivation_proof.as_ref().ok_or_else(|| {
        ErrorBadRequest("split spend proof requests require clientDerivationProof")
    })?;
    let proof = Proof(bytes_from_hex(proof_hex)?);
    let verifier_key: VerifierKey = tagged_deserialize(
        &include_bytes!("../../../../circuits/static/client-derivation/sk_prove.verifier")[..],
    )
    .map_err(|e| ErrorBadRequest(format!("deserialize client derivation verifier key: {e}")))?;
    let mut statement = vec![Fr::from(0u64)];
    statement.extend(client_derivation_public_transcript_inputs(
        pk,
        nullifier.0.0,
        coin_binding_tag,
        commitment_sk,
    ));
    verifier_key
        .verify_poseidon(&PARAMS_VERIFIER, &proof, statement.into_iter())
        .map_err(|e| ErrorBadRequest(format!("invalid client derivation proof: {e}")))
}

/// v3 fast-fail attestation pre-verify. Mirrors what the node admission
/// verifier does (`deps/midnight-ledger/zswap/src/verify.rs`) so the proof
/// server can reject bad attestations before doing any prover work.
async fn verify_attestation_proof(
    attestation_proof_hex: &str,
    pk: CoinPublicKey,
    commitment_sk: Fr,
) -> Result<(), Error> {
    let proof = Proof(bytes_from_hex(attestation_proof_hex)?);
    let verifier_key: VerifierKey =
        tagged_deserialize(
            &include_bytes!(
                "../../../../circuits/static/wallet-attestation/wallet_attest.verifier"
            )[..],
        )
        .map_err(|e| {
            ErrorBadRequest(format!("deserialize wallet attestation verifier key: {e}"))
        })?;
    let mut statement = vec![Fr::from(0u64)];
    statement.extend(wallet_attestation_public_transcript_inputs(
        pk,
        commitment_sk,
    ));
    verifier_key
        .verify_poseidon(&PARAMS_VERIFIER, &proof, statement.into_iter())
        .map_err(|e| ErrorBadRequest(format!("invalid wallet attestation proof: {e}")))
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
    // v3 cell 3 — Poseidon C_sk; cross-checked against the attestation.
    extend_ops(
        &mut inputs,
        Cell_write!([Key::Value(3u8.into())], false, Fr, commitment_sk),
    );
    inputs
}

fn wallet_attestation_public_transcript_inputs(pk: CoinPublicKey, commitment_sk: Fr) -> Vec<Fr> {
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

fn extend_ops<const N: usize>(inputs: &mut Vec<Fr>, ops: [Op<ResultModeVerify, InMemoryDB>; N]) {
    for op in ops.into_iter().filter(|op| match op {
        Op::Idx { path, .. } => !path.is_empty(),
        Op::Ins { n, .. } => *n != 0,
        _ => true,
    }) {
        op.field_repr(inputs);
    }
}

impl TryFrom<SplitProvingData> for ProvingKeyMaterial {
    type Error = Error;

    fn try_from(value: SplitProvingData) -> Result<Self, Self::Error> {
        Ok(ProvingKeyMaterial {
            prover_key: bytes_from_hex(&value.prover_key)?,
            verifier_key: bytes_from_hex(&value.verifier_key)?,
            ir_source: bytes_from_hex(&value.ir_source)?,
        })
    }
}

fn bytes32_from_hex(value: &str) -> Result<[u8; 32], Error> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    let bytes = bytes_from_hex(value)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        ErrorBadRequest(format!("expected 32 bytes, got {}", bytes.len()))
    })
}

fn bytes_from_hex(value: &str) -> Result<Vec<u8>, Error> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    hex::decode(value).map_err(|e| ErrorBadRequest(format!("invalid hex: {e}")))
}

fn work_error_message(error: WorkError) -> String {
    match error {
        WorkError::BadInput(message) | WorkError::InternalError(message) => message,
        WorkError::CancelledUnexpectedly => "work cancelled unexpectedly".to_string(),
        WorkError::JoinError => "task join error".to_string(),
    }
}

fn fr_from_hex(value: &str) -> Result<Fr, Error> {
    let bytes = bytes32_from_hex(value)?;
    Fr::from_le_bytes(&bytes).ok_or_else(|| ErrorBadRequest("invalid field element"))
}

#[derive(Clone, Copy, serde::Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
enum Status {
    Ok,
    Busy,
}

impl From<Status> for StatusCode {
    fn from(val: Status) -> Self {
        match val {
            Status::Ok => StatusCode::OK,
            Status::Busy => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadyResponse {
    status: Status,
    jobs_processing: usize,
    jobs_pending: usize,
    job_capacity: usize,
    timestamp: time::OffsetDateTime,
}

#[get("/ready")]
pub(crate) async fn ready(pool: web::Data<Arc<WorkerPool>>) -> Result<HttpResponse, Error> {
    let jobs_processing = pool.requests.processing_count().await;
    let jobs_pending = pool.requests.pending_count().await;
    let job_capacity = pool.requests.capacity;
    let status = ReadyResponse {
        status: if pool.requests.is_full().await {
            Status::Busy
        } else {
            Status::Ok
        },
        jobs_processing,
        jobs_pending,
        job_capacity,
        timestamp: time::OffsetDateTime::now_utc(),
    };

    let builder = HttpResponseBuilder::new(status.status.into()).json(status);
    Ok(builder)
}

#[get("/proof-versions")]
pub(crate) async fn proof_versions() -> impl Responder {
    let mut fields = ProofVersioned::introspection().fields;
    fields.retain(|x| x != "Dummy");
    format!("{:?}", fields)
}

#[post("/k")]
pub(crate) async fn get_k(payload: Payload) -> Result<HttpResponse, Error> {
    info!("Starting to process request for /k...");
    let request = payload_to_bytes(payload).await?;
    debug!(
        "Received request: {}",
        (&request[..]).encode_hex::<String>()
    );

    let k = versioned_ir::k(&request).map_err(ErrorBadRequest)?;

    Ok(HttpResponse::Ok().body(format!("{k}")))
}

#[post("/check")]
pub(crate) async fn check(
    pool: Data<Arc<WorkerPool>>,
    payload: Payload,
) -> Result<HttpResponse, Error> {
    info!("Starting to process request for /check...");
    let request = payload_to_bytes(payload).await?;
    debug!(
        "Received request: {}",
        (&request[..]).encode_hex::<String>()
    );
    let (ppi, ir): (ProofPreimageVersioned, Option<WrappedIr>) =
        tagged_deserialize(&request[..]).map_err(ErrorBadRequest)?;
    let (_id, updates) = pool
        .submit_and_subscribe(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let ir = match ir {
                    Some(ir) => ir.0,
                    None => {
                        let resolver = Resolver::new(
                            PUBLIC_PARAMS.clone(),
                            DustResolver(
                                MidnightDataProvider::new(
                                    FetchMode::OnDemand,
                                    OutputMode::Log,
                                    ledger::dust::DUST_EXPECTED_FILES.to_owned(),
                                )
                                .expect("data provider initialization failed"),
                            ),
                            Box::new(move |_: KeyLocation| Box::pin(std::future::ready(Ok(None)))),
                        );
                        let proof_data = resolver
                            .resolve_key(ppi.key_location().clone())
                            .await
                            .map_err(|e| WorkError::BadInput(e.to_string()))?;

                        proof_data
                            .ok_or_else(|| {
                                WorkError::BadInput(format!(
                                    "couldn't find built-in key {}",
                                    &ppi.key_location().0
                                ))
                            })?
                            .ir_source
                    }
                };
                let result = match ppi {
                    ProofPreimageVersioned::V2(ppi) => {
                        versioned_ir::check(ppi, &ir).map_err(WorkError::BadInput)?
                    }
                    // Footgun: If we add a new version, this needs to be covered here, but it's marked
                    // #[non_exhaustive], so we always need the base case.
                    _ => unreachable!(),
                };
                let result = result
                    .into_iter()
                    .map(|i| i.map(|i| i as u64))
                    .collect::<Vec<_>>();
                let mut response = Vec::new();
                tagged_serialize(&result, &mut response)
                    .map_err(|e| WorkError::InternalError(e.to_string()))?;
                Ok(response)
            })
        })
        .await?;
    let response = JobStatus::wait_for_success(&updates).await?;

    Ok(HttpResponse::Ok().body(response))
}

#[post("/prove")]
pub(crate) async fn prove(
    pool: Data<Arc<WorkerPool>>,
    payload: Payload,
) -> Result<HttpResponse, Error> {
    info!("Starting to process request for /prove...");
    let request = payload_to_bytes(payload).await?;
    debug!(
        "Received request: {}",
        (&request[..]).encode_hex::<String>()
    );
    let (ppi, data, binding_input): (
        ProofPreimageVersioned,
        Option<ProvingKeyMaterial>,
        Option<Fr>,
    ) = tagged_deserialize(&request[..]).map_err(ErrorBadRequest)?;

    let data_resolver = data.clone();
    let (_id, updates) = pool
        .submit_and_subscribe(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let resolver = Resolver::new(
                    PUBLIC_PARAMS.clone(),
                    DustResolver(
                        MidnightDataProvider::new(
                            FetchMode::OnDemand,
                            OutputMode::Log,
                            ledger::dust::DUST_EXPECTED_FILES.to_owned(),
                        )
                        .expect("data provider initialization failed"),
                    ),
                    Box::new(move |_: KeyLocation| {
                        Box::pin(std::future::ready(Ok(data_resolver.clone())))
                    }),
                );
                let proof = match ppi {
                    ProofPreimageVersioned::V2(mut ppi) => {
                        if let Some(binding_input) = binding_input {
                            let mut inner = (*ppi).clone();
                            inner.binding_input = binding_input;
                            ppi = Arc::new(inner);
                        }
                        let proving_data = match data {
                            Some(pkm) => pkm,
                            None => resolver
                                .resolve_key(ppi.key_location.clone())
                                .await
                                .map_err(|e| WorkError::BadInput(e.to_string()))?
                                .ok_or_else(|| {
                                    WorkError::BadInput(format!(
                                        "couldn't find key {}",
                                        &ppi.key_location.0
                                    ))
                                })?,
                        };

                        let proof = versioned_ir::prove(ppi, &proving_data.ir_source, &resolver)
                            .await
                            .map_err(WorkError::BadInput)?
                            .0;

                        ProofVersioned::V2(proof)
                    }
                    // Footgun: If we add a new version, this needs to be covered here, but it's marked
                    // #[non_exhaustive], so we always need the base case.
                    _ => unreachable!(),
                };
                let mut response = Vec::new();
                tagged_serialize(&proof, &mut response)
                    .map_err(|e| WorkError::InternalError(e.to_string()))?;
                Ok(response)
            })
        })
        .await?;
    let response = JobStatus::wait_for_success(&updates).await?;

    Ok(HttpResponse::Ok().body(response))
}

#[post("/prove-tx")]
pub(crate) async fn prove_transaction(
    pool: Data<Arc<WorkerPool>>,
    payload: Payload,
) -> Result<HttpResponse, Error> {
    info!("Starting to process request for /prove-tx...");
    let request = payload_to_bytes(payload).await?;
    debug!(
        "Received request: {}",
        (&request[..]).encode_hex::<String>()
    );
    let (tx, keys): TransactionProvePayload<Signature> =
        tagged_deserialize(&request[..]).map_err(ErrorBadRequest)?;
    let (_id, updates) = pool
        .submit_and_subscribe(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let mut response = Vec::new();
                let resolver = Resolver::new(
                    PUBLIC_PARAMS.clone(),
                    DustResolver(
                        MidnightDataProvider::new(
                            FetchMode::OnDemand,
                            OutputMode::Log,
                            ledger::dust::DUST_EXPECTED_FILES.to_owned(),
                        )
                        .expect("data provider initialization failed"),
                    ),
                    Box::new(move |loc| {
                        Box::pin(std::future::ready(Ok(keys.get(loc.0.as_ref()).cloned())))
                    }),
                );
                let provider = zkir_v2::LocalProvingProvider {
                    rng: OsRng,
                    params: &resolver,
                    resolver: &resolver,
                };
                // NOTE: The initial cost model here is part of why this is deprecated!
                // Use /prove instead!
                tagged_serialize(
                    &tx.prove(provider, &INITIAL_TRANSACTION_COST_MODEL.runtime_cost_model)
                        .await
                        .map_err(|e| WorkError::BadInput(e.to_string()))?,
                    &mut response,
                )
                .map_err(|e| WorkError::InternalError(e.to_string()))?;
                Ok(response)
            })
        })
        .await?;
    let response = JobStatus::wait_for_success(&updates).await?;
    Ok(HttpResponse::Ok().body(response))
}
