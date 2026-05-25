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
use actix_cors::Cors;
use actix_web::dev::Server;
use actix_web::middleware::Logger;
use actix_web::web::{self, Data};
use actix_web::{App, HttpServer};
use std::sync::Arc;

use crate::endpoints::{
    check, fetch_k, get_k, health, proof_versions, prove, prove_split_spend, prove_transaction,
    ready, version,
};
use crate::worker_pool::WorkerPool;

pub mod endpoints;
pub mod preview_client;
pub mod versioned_ir;
pub mod worker_pool;

/// Solution A: install a registry-root checker into Zswap's admission path.
///
/// **Demo mode** — installs a permissive checker that accepts any root.
/// Used by the live preview e2e where the synthetic single-leaf registry
/// tree the wallet builds in-memory (`PreviewRegistryWitness::
/// for_first_registration`) has no corresponding deployed contract whose
/// history can be consulted.
///
/// Production deployments call `install_registry_root_checker_from_ledger`
/// instead, which:
///   1. reads the registry contract address from
///      `circuits/static/wallet-registry/contract_address.txt` (or
///      `WALLET_REGISTRY_CONTRACT_ADDRESS` env),
///   2. resolves the deployed contract from a live `LedgerState`,
///   3. extracts every `MerkleTreeDigest` from its `ChargedState` via
///      `ledger::verify::wallet_registry_root_check`, and
///   4. installs a closure that returns `true` iff `root` is in that set.
pub fn install_registry_root_checker_for_demo() {
    zswap::verify::install_registry_root_checker(Box::new(|_root| true));
    tracing::warn!(
        "Solution A: demo-mode registry-root checker installed (accepts all roots). \
         Wire a real checker against the deployed registry contract for production."
    );
}

/// Production wiring of `install_registry_root_checker` — extracts the
/// admissible-root set from the live ledger state at boot and installs a
/// closure that admits only those roots.
///
/// This is the bridge between the `StateReference::wallet_registry_root_check`
/// abstraction in the ledger crate and Zswap's process-wide `RegistryRootChecker`.
/// Call once at startup, after the proof-server has fetched the latest
/// `LedgerState` from the indexer; re-call when the contract's state moves
/// (the closure captures a snapshot, so it must be reinstalled as the tree
/// grows).
pub fn install_registry_root_checker_from_ledger<D: storage::db::DB>(
    state: &ledger::structure::LedgerState<D>,
) -> Result<usize, &'static str> {
    let address = ledger::verify::wallet_registry_contract_address()
        .ok_or("registry contract address not configured (set WALLET_REGISTRY_CONTRACT_ADDRESS \
                or place a deployed address in circuits/static/wallet-registry/contract_address.txt)")?;
    let contract = state
        .index(address)
        .ok_or("registry contract not present in the supplied LedgerState")?;
    let roots = ledger::verify::extract_historic_roots_for(contract.data.get_ref());
    let count = roots.len();
    let admissible: std::collections::BTreeSet<_> = roots.into_iter().collect();
    zswap::verify::install_registry_root_checker(Box::new(move |root| {
        admissible.contains(&root)
    }));
    tracing::info!(
        "Solution A: installed registry-root checker with {} admissible roots from contract {:?}",
        count, address
    );
    Ok(count)
}

pub fn server(port: u16, fetch_params: bool, pool: WorkerPool) -> std::io::Result<(Server, u16)> {
    let pool = Arc::new(pool);
    let http_server = HttpServer::new(move || {
        let app = App::new()
            .app_data(Data::new(pool.clone()))
            .service(prove_transaction)
            .service(prove_split_spend)
            .service(prove)
            .service(check)
            .service(get_k)
            .service(version)
            .service(proof_versions)
            .service(ready)
            .route("/", web::get().to(health))
            .route("/health", web::get().to(health))
            .wrap(Logger::new("%a %r; took %Ts"))
            .wrap(Cors::permissive());
        if fetch_params {
            app.service(fetch_k)
        } else {
            app
        }
    })
    .bind(("0.0.0.0", port))?;
    let port = http_server.addrs()[0].port();
    let srv = http_server.run();
    Ok((srv, port))
}
