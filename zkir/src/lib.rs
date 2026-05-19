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

#[macro_use]
extern crate tracing;

use base_crypto::rng::SplittableRng;
use rand::{CryptoRng, Rng};
use serialize::tagged_deserialize;
use transient_crypto::curve::Fr;
use transient_crypto::proofs::{
    ParamsProverProvider, Proof, ProofPreimage, ProverKey, ProvingError, ProvingProvider, Resolver,
    VerifierKey,
};

mod ir;
mod ir_vm;

pub use ir::{Instruction, IrSource};
pub use ir_vm::Preprocessed;

/// Proves a ZKIR preimage with the Poseidon transcript used by recursive
/// verifier gadgets.
pub async fn prove_poseidon(
    preimage: &ProofPreimage,
    rng: impl Rng + CryptoRng,
    params: &impl ParamsProverProvider,
    resolver: &impl Resolver,
) -> Result<(Proof, Vec<Option<usize>>), ProvingError> {
    let proof_data = resolver
        .resolve_key(preimage.key_location.clone())
        .await?
        .ok_or(anyhow::Error::msg(format!(
            "failed to find proving key for '{}'",
            &preimage.key_location.0
        )))?;
    let ir = tagged_deserialize::<IrSource>(&mut &proof_data.ir_source[..])?;
    let verifier_key = tagged_deserialize::<VerifierKey>(&mut &proof_data.verifier_key[..])?;
    let prover_key = tagged_deserialize::<ProverKey<IrSource>>(&mut &proof_data.prover_key[..])?;
    let (proof, pis, pi_skips) = ir.prove_poseidon(rng, params, prover_key, preimage).await?;
    debug!("Poseidon proof created; verifying to make sure");
    let k = verifier_key.midnight_vk()?.k();
    if let Err(e) = verifier_key.verify_poseidon(
        &params.get_params(k).await?.as_verifier(),
        &proof,
        pis.iter().copied(),
    ) {
        error!(error = ?e, ?pis, ?ir, "Poseidon self-verification failed! This may be a bug, check that your keys match!");
        return Err(e);
    }
    debug!("Poseidon proof ok");
    Ok((proof, pi_skips))
}

/// Implements `ProvingProvider` locally
pub struct LocalProvingProvider<
    'a,
    R: Rng + CryptoRng + SplittableRng,
    S: Resolver,
    P: ParamsProverProvider,
> {
    /// The randomness to use for proving
    pub rng: R,
    /// The resolver to use to fetch keys
    pub resolver: &'a S,
    /// The parameters provider to use
    pub params: &'a P,
}

impl<'a, R: Rng + CryptoRng + SplittableRng, S: Resolver, P: ParamsProverProvider> ProvingProvider
    for LocalProvingProvider<'a, R, S, P>
{
    async fn check(&self, preimage: &ProofPreimage) -> Result<Vec<Option<usize>>, anyhow::Error> {
        let proving_data = self
            .resolver
            .resolve_key(preimage.key_location.clone())
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "attempted to check proof for '{}' without circuit data!",
                    preimage.key_location.0
                )
            })?;
        let ir: IrSource = tagged_deserialize(&mut &proving_data.ir_source[..])?;
        preimage.check(&ir)
    }
    async fn prove(
        self,
        preimage: &ProofPreimage,
        overwrite_binding_input: Option<Fr>,
    ) -> Result<Proof, anyhow::Error> {
        let mut preimage = preimage.clone();
        if let Some(binding_input) = overwrite_binding_input {
            preimage.binding_input = binding_input;
        }
        Ok(preimage
            .prove::<IrSource>(self.rng, self.params, self.resolver)
            .await?
            .0)
    }
    fn split(&mut self) -> Self {
        Self {
            rng: self.rng.split(),
            resolver: self.resolver,
            params: self.params,
        }
    }
}
