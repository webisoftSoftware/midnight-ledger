// This file is part of midnight-ledger.
// Copyright (C) 2025 Midnight Foundation
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0

use base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};
use midnight_proofs::plonk::k_from_circuit;
use midnight_zswap::split_wrapper::{
    SPLIT_WRAPPER_K, SplitWrapperCircuit, keygen_split_wrapper, split_wrapper_inner_keys,
    write_split_wrapper_proving_key, write_split_wrapper_verifying_key,
};
use midnight_zswap::verify::{CLIENT_DERIVATION_VK, SPEND_SPLIT_VK, WALLET_ATTESTATION_VK};
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use transient_crypto::proofs::ParamsProverProvider;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let provider = MidnightDataProvider::new(
        FetchMode::OnDemand,
        OutputMode::Log,
        midnight_zswap::ZSWAP_EXPECTED_FILES.to_vec(),
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let params = runtime.block_on(provider.get_params(SPLIT_WRAPPER_K))?;
    let inner_keys = split_wrapper_inner_keys(
        &WALLET_ATTESTATION_VK,
        &CLIENT_DERIVATION_VK,
        &SPEND_SPLIT_VK,
    )?;
    let model_k = k_from_circuit(&SplitWrapperCircuit::without_witnesses_for_keys(
        inner_keys.clone(),
    ));
    eprintln!("split wrapper circuit min_k={model_k}; configured K={SPLIT_WRAPPER_K}");
    let (proving_key, verifying_key) = keygen_split_wrapper(&params, &inner_keys)?;

    let static_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("static");
    let ledger_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("zswap crate lives under the ledger workspace");
    let verifier_params = params.as_verifier();
    write_file(
        &ledger_dir
            .join("transient-crypto")
            .join("static")
            .join(format!("bls_midnight_2p{SPLIT_WRAPPER_K}.verifier")),
        |file| verifier_params.write(file),
    )?;
    write_file(&static_dir.join("spend-split-wrapper.prover"), |file| {
        write_split_wrapper_proving_key(&proving_key, file)
    })?;
    write_file(&static_dir.join("spend-split-wrapper.verifier"), |file| {
        write_split_wrapper_verifying_key(&verifying_key, file)
    })?;
    Ok(())
}

fn write_file(path: &Path, write: impl FnOnce(&mut File) -> io::Result<()>) -> io::Result<()> {
    let mut file = File::create(path)?;
    write(&mut file)?;
    file.flush()
}
