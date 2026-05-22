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
/// **Demo mode** — this installs a permissive checker that accepts any root.
/// For the live preview e2e the synthetic single-leaf registry tree the
/// wallet uses (`PreviewRegistryWitness::for_first_registration`) doesn't
/// have a corresponding deployed contract whose history can be consulted, so
/// admission accepts any well-formed `registry_root` field.
///
/// Production deployments must replace this with a checker that:
///   1. reads the registry contract address from
///      `circuits/static/wallet-registry/contract_address.txt`,
///   2. resolves the deployed contract from the live `LedgerState`,
///   3. extracts its `HistoricMerkleTree<20>` ledger cell, and
///   4. returns `true` iff `root` is in that cell's root history.
///
/// See `tools/deploy_registry.sh` for the address-resolution step and
/// `StateReference::wallet_registry_root_check` for the trait surface this
/// would call into.
pub fn install_registry_root_checker_for_demo() {
    zswap::verify::install_registry_root_checker(Box::new(|_root| true));
    tracing::warn!(
        "Solution A: demo-mode registry-root checker installed (accepts all roots). \
         Wire a real checker against the deployed registry contract for production."
    );
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
