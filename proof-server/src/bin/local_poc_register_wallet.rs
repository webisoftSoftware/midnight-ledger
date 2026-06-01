// This file is part of midnight-ledger.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: Apache-2.0

//! Phase 2 helper: derive the wallet's `reg_leaf` (Solution A attestation
//! circuit), then submit a `register(reg_leaf)` contract call to the
//! genesis-deployed `wallet_registry`. Idempotent — if the leaf is
//! already on-chain, the program exits 0 without resubmitting.

use clap::Parser;
use midnight_proof_server::local_poc_client::{
    self, LocalPocResult, env_value, local_poc_env, prove_wallet_attestation,
    repo_root_tool,
};
use midnight_proof_server::wallet_registry_call::{
    RegisterCallOutcome, build_register_call_tx_hex,
};
use std::process::Command;
use tracing::{Level, info};
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, Registry};

#[derive(Parser, Debug)]
struct Args {
    /// Index of the local wallet's zswap key to register. Must match the
    /// key index the rest of the e2e flow uses for split spends.
    #[arg(long, env = "MIDNIGHT_LOCAL_ZSWAP_KEY_INDEX", default_value_t = 0)]
    key_index: usize,
    /// Optional explicit proof-server URL. The register call only uses
    /// the local proving path, but the JS-side balance/submit step
    /// forwards it to the wallet SDK for its own zswap output proofs.
    #[arg(long, env = "MIDNIGHT_PROOF_SERVER_URL")]
    proof_server_url: Option<String>,
    /// Skip the actual submission step; produce only the tx hex on stdout.
    #[arg(long)]
    dry_run: bool,
    #[arg(short, long, env = "MIDNIGHT_PROOF_SERVER_VERBOSE")]
    verbose: bool,
}

#[actix_web::main]
async fn main() -> LocalPocResult<()> {
    let args = Args::parse();
    init_logging(args.verbose);

    let env = local_poc_env();
    let secret_keys = local_poc_client::local_zswap_secret_keys_scan(&env)?;
    let scanned = secret_keys.len();
    let (_, keys) = secret_keys
        .iter()
        .find(|(idx, _)| *idx == args.key_index)
        .ok_or_else(|| {
            format!(
                "no scanned wallet key matches --key-index {} (scanned {scanned} keys)",
                args.key_index,
            )
        })?;

    info!(stage = "attestation", "▶ deriving wallet reg_leaf");
    let registration =
        prove_wallet_attestation(&keys.coin_secret_key, &env, args.key_index).await?;
    info!(
        stage = "attestation",
        reg_leaf = %hex::encode(registration.reg_leaf_bytes),
        "✓ reg_leaf derived"
    );

    info!(stage = "build-tx", "▶ querying chain + building register tx");
    let outcome = build_register_call_tx_hex(registration.reg_leaf_bytes, &env).await?;

    let tx_hex = match outcome {
        RegisterCallOutcome::AlreadyRegistered {
            registry_address,
            leaf_index,
        } => {
            info!(
                registry_address = %hex::encode(registry_address.0.0),
                leaf_index = leaf_index,
                "wallet already registered; nothing to submit"
            );
            println!(
                "{}",
                serde_json::json!({
                    "status": "already_registered",
                    "registryAddress": hex::encode(registry_address.0.0),
                    "leafIndex": leaf_index,
                    "regLeaf": hex::encode(registration.reg_leaf_bytes),
                })
            );
            return Ok(());
        }
        RegisterCallOutcome::TxBuilt {
            registry_address,
            tx_hex,
        } => {
            info!(
                registry_address = %hex::encode(registry_address.0.0),
                tx_hex_len = tx_hex.len(),
                "✓ register tx proved + sealed"
            );
            tx_hex
        }
    };

    if args.dry_run {
        println!(
            "{}",
            serde_json::json!({
                "status": "dry_run",
                "txHex": tx_hex,
                "regLeaf": hex::encode(registration.reg_leaf_bytes),
            })
        );
        return Ok(());
    }

    let proof_server_url = args
        .proof_server_url
        .or_else(|| {
            let v = env_value(&env, "MIDNIGHT_PROOF_SERVER_URL");
            if v.trim().is_empty() { None } else { Some(v) }
        })
        .unwrap_or_else(|| "http://127.0.0.1:6300".to_string());

    info!(stage = "balance-submit", "▶ delegating to wallet SDK helper");
    let mjs_path = repo_root_tool("tools/local_balance_submit_split_tx.mjs")?;
    let output = Command::new("node")
        .arg(&mjs_path)
        .arg("--tx-hex")
        .arg(&tx_hex)
        .arg("--key-index")
        .arg(args.key_index.to_string())
        .arg("--proof-server-url")
        .arg(&proof_server_url)
        .arg("--submit")
        .envs(env.iter())
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "wallet SDK balance/submit failed: stderr={} stdout={}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        )
        .into());
    }

    let submission: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|e| {
            format!(
                "submission helper emitted non-JSON stdout: {e}; raw={}",
                String::from_utf8_lossy(&output.stdout)
            )
        })?;

    info!(
        tx_hash = %submission["txHash"].as_str().unwrap_or_default(),
        tx_id = %submission["txId"].as_str().unwrap_or_default(),
        block_hash = %submission["blockHash"].as_str().unwrap_or_default(),
        inclusion_status = %submission["inclusionStatus"].as_str().unwrap_or_default(),
        "✓ register(leaf) included on-chain"
    );

    println!(
        "{}",
        serde_json::json!({
            "status": "submitted",
            "regLeaf": hex::encode(registration.reg_leaf_bytes),
            "submission": submission,
        })
    );

    Ok(())
}

fn init_logging(verbose: bool) {
    let level = if verbose { Level::DEBUG } else { Level::INFO };
    Registry::default()
        .with(
            tracing_subscriber::fmt::layer().with_filter(
                Targets::new()
                    .with_default(level)
                    .with_target("zkir", tracing_subscriber::filter::LevelFilter::OFF),
            ),
        )
        .try_init()
        .ok();
}
