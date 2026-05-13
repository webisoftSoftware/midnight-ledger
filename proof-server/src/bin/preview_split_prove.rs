// This file is part of midnight-ledger.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: Apache-2.0

use actix_web::rt;
use clap::Parser;
use midnight_proof_server::preview_client::{
    PreviewSplitProveOptions, prove_preview_wallet_split_spend,
};
use midnight_proof_server::{server, worker_pool::WorkerPool};
use tracing::{Level, info};
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, Registry};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, env = "MIDNIGHT_PROOF_SERVER_URL")]
    proof_server_url: Option<String>,
    #[arg(long, default_value_t = 2, env = "MIDNIGHT_PROOF_SERVER_NUM_WORKERS")]
    num_workers: usize,
    #[arg(long, default_value_t = 2, env = "MIDNIGHT_PROOF_SERVER_JOB_CAPACITY")]
    job_capacity: usize,
    #[arg(
        long,
        default_value_t = 600.0,
        env = "MIDNIGHT_PROOF_SERVER_JOB_TIMEOUT"
    )]
    job_timeout: f64,
    #[arg(long, env = "MIDNIGHT_PREVIEW_ZSWAP_EVENT_LIMIT")]
    event_limit: Option<usize>,
    #[arg(
        long,
        default_value_t = 120,
        env = "MIDNIGHT_PREVIEW_REQUEST_TIMEOUT_SECS"
    )]
    request_timeout_secs: u64,
    #[arg(short, long, env = "MIDNIGHT_PROOF_SERVER_VERBOSE")]
    verbose: bool,
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();
    init_logging(args.verbose);

    let (proof_server_url, handle) = if let Some(url) = args.proof_server_url {
        (url.trim_end_matches('/').to_string(), None)
    } else {
        let pool = WorkerPool::new(args.num_workers, args.job_capacity, args.job_timeout);
        let (srv, port) = server(0, false, pool)?;
        let handle = srv.handle();
        rt::spawn(srv);
        let url = format!("http://127.0.0.1:{port}");
        info!("started local proof server at {url}");
        (url, Some(handle))
    };

    let result = prove_preview_wallet_split_spend(PreviewSplitProveOptions {
        proof_server_url: &proof_server_url,
        event_limit: args.event_limit,
        request_timeout_secs: args.request_timeout_secs,
    })
    .await;

    if let Some(handle) = handle {
        handle.stop(false).await;
    }

    let report = result?;
    println!(
        "split-sent preview output key_index={} mt_index={} input_value={} transfer_value={} change_value={} token={} recipient={} status={} proof_len={} tx_hash={} tx_id={} tx_len={}",
        report.key_index,
        report.mt_index,
        report.coin_value,
        report.transfer_value,
        report.change_value,
        report.token_type_hex,
        report.recipient_shielded_address,
        report.status,
        report.proof_hex_len,
        report.tx_hash,
        report.tx_id.as_deref().unwrap_or(""),
        report.tx_hex_len,
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
