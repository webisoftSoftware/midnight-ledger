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

#[cfg(feature = "proof-verifying")]
use crate::ciphertext_to_field;
use crate::error::MalformedOffer;
#[cfg(any(feature = "proof-verifying", test))]
use crate::filter_invalid;
#[cfg(feature = "proof-verifying")]
use crate::split_wrapper::{
    SPLIT_WRAPPER_K, SplitWrapperInnerKeys, SplitWrapperProofBundle, SplitWrapperVerifyingKey,
    read_split_wrapper_verifying_key, split_wrapper_inner_keys, verify_split_wrapper,
    wrapper_public_input_statement,
};
use crate::structure::*;
#[cfg(feature = "proof-verifying")]
use base_crypto::fab::AlignedValue;
#[cfg(test)]
use coin_structure::contract::ContractAddress;
#[cfg(feature = "proof-verifying")]
use serialize::Deserializable;
#[cfg(feature = "proof-verifying")]
use serialize::tagged_deserialize;
use storage::db::DB;
use storage::db::InMemoryDB;
use storage::{Storable, arena::Sp};
use transient_crypto::commitment::Pedersen;
use transient_crypto::curve::{EmbeddedFr, EmbeddedGroupAffine, Fr};
#[cfg(feature = "proof-verifying")]
use transient_crypto::hash::transient_commit;
use transient_crypto::proofs::PARAMS_VERIFIER;
#[cfg(feature = "proof-verifying")]
use transient_crypto::proofs::{ParamsVerifier, VerifierKey};
use transient_crypto::proofs::{Proof, ProofPreimage};
#[cfg(any(feature = "proof-verifying", test))]
use transient_crypto::repr::FieldRepr;
// On nightly this becomes a noop
#[allow(unused_imports)]
use is_sorted::IsSorted;
#[cfg(any(feature = "proof-verifying", test))]
use midnight_onchain_runtime::ops::{Key, Op};
#[cfg(any(feature = "proof-verifying", test))]
use midnight_onchain_runtime::program_fragments::*;
#[cfg(feature = "proof-verifying")]
use midnight_onchain_runtime::result_mode::{ResultModeGather, ResultModeVerify};
#[cfg(any(feature = "proof-verifying", test))]
use midnight_onchain_runtime::state::StateValue;
use std::ops::Add;
use std::ops::Deref;
#[cfg(any(feature = "proof-verifying", test))]
use std::sync::Arc;

#[cfg(feature = "proof-verifying")]
const OUTPUT_VK_RAW: &[u8] = include_bytes!("../static/output.verifier");
#[cfg(feature = "proof-verifying")]
const SPEND_VK_RAW: &[u8] = include_bytes!("../static/spend.verifier");
#[cfg(feature = "proof-verifying")]
const SPEND_SPLIT_VK_RAW: &[u8] = include_bytes!("../static/spend-split.verifier");
#[cfg(feature = "proof-verifying")]
const CLIENT_DERIVATION_VK_RAW: &[u8] = include_bytes!("../static/client-derivation.verifier");
#[cfg(feature = "proof-verifying")]
const WALLET_ATTESTATION_VK_RAW: &[u8] = include_bytes!("../static/wallet-attestation.verifier");
#[cfg(feature = "proof-verifying")]
const SIGN_VK_RAW: &[u8] = include_bytes!("../static/sign.verifier");
#[cfg(feature = "proof-verifying")]
const SIGN_SPLIT_VK_RAW: &[u8] = include_bytes!("../static/sign-split.verifier");
#[cfg(feature = "proof-verifying")]
const SPEND_SPLIT_WRAPPER_VK_RAW: &[u8] = include_bytes!("../static/spend-split-wrapper.verifier");

#[cfg(feature = "proof-verifying")]
lazy_static! {
    pub static ref OUTPUT_VK: VerifierKey =
        tagged_deserialize(&mut OUTPUT_VK_RAW.to_vec().as_slice())
            .expect("Zswap Output VK should be valid");
    pub static ref SPEND_VK: VerifierKey =
        tagged_deserialize(&mut SPEND_VK_RAW.to_vec().as_slice())
            .expect("Zswap Spend VK should be valid");
    pub static ref SPEND_SPLIT_VK: VerifierKey =
        tagged_deserialize(&mut SPEND_SPLIT_VK_RAW.to_vec().as_slice())
            .expect("Zswap Split Spend VK should be valid");
    pub static ref CLIENT_DERIVATION_VK: VerifierKey =
        tagged_deserialize(&mut CLIENT_DERIVATION_VK_RAW.to_vec().as_slice())
            .expect("Zswap Client Derivation VK should be valid");
    pub static ref WALLET_ATTESTATION_VK: VerifierKey =
        tagged_deserialize(&mut WALLET_ATTESTATION_VK_RAW.to_vec().as_slice())
            .expect("Zswap Wallet Attestation VK should be valid");
    pub static ref SIGN_VK: VerifierKey = tagged_deserialize(&mut SIGN_VK_RAW.to_vec().as_slice())
        .expect("Zswap Sign VK should be valid");
    pub static ref SIGN_SPLIT_VK: VerifierKey =
        tagged_deserialize(&mut SIGN_SPLIT_VK_RAW.to_vec().as_slice())
            .expect("Zswap Split Sign VK should be valid");
    pub static ref SPEND_SPLIT_WRAPPER_VK: SplitWrapperVerifyingKey =
        read_split_wrapper_verifying_key(SPEND_SPLIT_WRAPPER_VK_RAW)
            .expect("Zswap Split Wrapper VK should be valid");
    pub static ref SPLIT_WRAPPER_PARAMS_VERIFIER: ParamsVerifier =
        ParamsVerifier::read_cached_prover(SPLIT_WRAPPER_K)
            .expect("Zswap Split Wrapper verifier params should be valid");
    pub static ref SPLIT_WRAPPER_INNER_KEYS: SplitWrapperInnerKeys = split_wrapper_inner_keys(
        &WALLET_ATTESTATION_VK,
        &CLIENT_DERIVATION_VK,
        &SPEND_SPLIT_VK,
    )
    .expect("Zswap Split Wrapper inner verifier keys should be valid");
}

#[cfg(feature = "proof-verifying")]
pub fn with_outputs<
    'a,
    A: Iterator<Item = Op<ResultModeGather, D>> + 'a,
    B: Iterator<Item = AlignedValue> + 'a,
    D: DB,
>(
    prog: A,
    mut values: B,
) -> impl Iterator<Item = Op<ResultModeVerify, D>> + 'a {
    filter_invalid(prog).map(move |op| {
        op.translate(|()| {
            values
                .next()
                .expect("must have sufficient values to annotate operations")
        })
    })
}

#[cfg(any(test, feature = "proof-verifying"))]
const CADDR_OP_LEN: u32 = 12;

#[cfg(test)]
#[test]
fn test_caddr_op() {
    let mut repr = Vec::new();
    for op in filter_invalid::<
        ResultModeVerify,
        std::array::IntoIter<Op<ResultModeVerify, InMemoryDB>, 5>,
        InMemoryDB,
    >(
        Cell_write!(
            [Key::Value(3u8.into())],
            false,
            ContractAddress,
            ContractAddress::default()
        )
        .into_iter(),
    ) {
        op.field_repr(&mut repr);
    }
    assert_eq!(repr.len(), CADDR_OP_LEN as usize);
}

impl AuthorizedClaim<Proof> {
    #[cfg(not(feature = "proof-verifying"))]
    pub fn well_formed(&self) -> Result<(), MalformedOffer> {
        Ok(())
    }

    #[cfg(feature = "proof-verifying")]
    pub fn well_formed(&self) -> Result<(), MalformedOffer> {
        use storage::db::InMemoryDB;

        let prog: [Op<ResultModeVerify, InMemoryDB>; 5] = Cell_write!(
            [Key::Value(4u8.into())],
            false,
            CoinPublicKey,
            self.recipient
        );
        let mut statement = vec![transient_commit(&self.coin, 0u8.into())];
        for op in filter_invalid(prog.iter().cloned()) {
            op.field_repr(&mut statement);
        }
        if SIGN_VK
            .verify(&PARAMS_VERIFIER, &self.proof, statement.iter().copied())
            .is_ok()
        {
            return Ok(());
        }
        SIGN_SPLIT_VK
            .verify(&PARAMS_VERIFIER, &self.proof, statement.iter().copied())
            .map_err(MalformedOffer::InvalidProof)
    }
}

impl<D: DB> Input<Proof, D> {
    #[cfg(not(feature = "proof-verifying"))]
    pub fn well_formed(&self, _segment: u16) -> Result<(), MalformedOffer> {
        Ok(())
    }

    #[instrument]
    #[cfg(feature = "proof-verifying")]
    pub fn well_formed(&self, segment: u16) -> Result<(), MalformedOffer> {
        let input_proof = ZswapInputProof::decode(&self.proof)
            .map_err(|_| MalformedOffer::MalformedSplitProofBundle)?;

        match input_proof {
            ZswapInputProof::SplitWrapped(split_bundle) => {
                return self.split_wrapper_well_formed(segment, &split_bundle);
            }
            ZswapInputProof::Split(_) => {
                return Err(MalformedOffer::MalformedSplitProofBundle);
            }
            ZswapInputProof::Plain(_) => {}
        }

        let mut prog = Vec::new();
        prog.extend::<[Op<ResultModeGather, InMemoryDB>; 6]>(HistoricMerkleTree_check_root!(
            [Key::Value(0u8.into())],
            false,
            32,
            [u8; 32],
            self.merkle_tree_root
        ));
        prog.extend(Set_insert!(
            [Key::Value(1u8.into())],
            false,
            [u8; 32],
            self.nullifier
        ));
        match &self.contract_address {
            Some(addr) => prog.extend(Cell_write!(
                [Key::Value(3u8.into())],
                false,
                ContractAddress,
                *addr.deref()
            )),
            None => prog.push(Op::Noop { n: CADDR_OP_LEN }),
        }
        prog.extend(Cell_read!([Key::Value(5u8.into())], false, u16));
        prog.extend(Cell_write!(
            [Key::Value(2u8.into())],
            false,
            (Fr, Fr),
            self.value_commitment.0
        ));
        let mut statement = vec![0.into()];
        for op in with_outputs(prog.into_iter(), [true.into(), segment.into()].into_iter()) {
            op.field_repr(&mut statement);
        }
        SPEND_VK
            .verify(&PARAMS_VERIFIER, &self.proof, statement.iter().copied())
            .map_err(MalformedOffer::InvalidProof)
    }

    #[cfg(feature = "proof-verifying")]
    #[allow(dead_code)]
    fn split_well_formed(
        &self,
        segment: u16,
        split_bundle: &SplitProofBundle,
    ) -> Result<(), MalformedOffer> {
        let split = &split_bundle.split_public_inputs;
        // v3 admission chain (plain Rust verification, no recursion in-circuit):
        //   (i)  attestation proof → asserts `pk == H(sk) ∧ C_sk == H(sk, r)`
        //        (Plan §"Soundness argument" step 1)
        //   (ii) client-derivation proof → opens `C_sk` to recover `sk`, then
        //        computes the canonical nullifier and coin-binding tag from
        //        that `sk` (Plan §"Soundness argument" steps 3–5)
        //   (iii) cross-checks across the two proofs:
        //        - both disclose the same `pk` (re-used as
        //          `split.public_key` here),
        //        - both disclose the same `commitment_sk` (re-used as
        //          `split.commitment_sk` here),
        //        which together force `sk` to be the same byte string on both
        //        sides under Poseidon binding (Plan §"Encoding pitfall").
        verify_wallet_attestation_proof(
            split.public_key,
            split.commitment_sk,
            &split_bundle.attestation_proof,
        )?;
        verify_client_derivation_proof(
            split,
            &split_bundle.client_derivation_proof,
            self.nullifier,
        )?;

        let mut split_prog = Vec::new();
        split_prog.extend::<[Op<ResultModeGather, InMemoryDB>; 6]>(HistoricMerkleTree_check_root!(
            [Key::Value(0u8.into())],
            false,
            32,
            [u8; 32],
            self.merkle_tree_root
        ));
        split_prog.extend(Cell_write!(
            [Key::Value(5u8.into())],
            false,
            [u8; 32],
            split.coin_commitment.0.0
        ));
        split_prog.extend(Cell_write!(
            [Key::Value(6u8.into())],
            false,
            Fr,
            split.coin_binding_tag
        ));
        split_prog.extend(Set_insert!(
            [Key::Value(1u8.into())],
            false,
            [u8; 32],
            self.nullifier
        ));
        if let Some(addr) = &self.contract_address {
            split_prog.extend(Cell_write!(
                [Key::Value(3u8.into())],
                false,
                ContractAddress,
                *addr.deref()
            ));
        }
        split_prog.extend(Cell_read!([Key::Value(7u8.into())], false, u16));
        split_prog.extend(Cell_write!(
            [Key::Value(2u8.into())],
            false,
            (Fr, Fr),
            self.value_commitment.0
        ));
        let mut split_statement = vec![0.into()];
        for op in with_outputs(
            split_prog.into_iter(),
            [true.into(), segment.into()].into_iter(),
        ) {
            op.field_repr(&mut split_statement);
        }
        SPEND_SPLIT_VK
            .verify(
                &PARAMS_VERIFIER,
                &split_bundle.spend_proof,
                split_statement.iter().copied(),
            )
            .map_err(MalformedOffer::InvalidProof)
    }

    #[cfg(feature = "proof-verifying")]
    fn split_wrapper_well_formed(
        &self,
        segment: u16,
        split_bundle: &SplitWrapperProofBundle,
    ) -> Result<(), MalformedOffer> {
        if self.contract_address.is_some() {
            return Err(MalformedOffer::MalformedSplitProofBundle);
        }
        let public_inputs = wrapper_public_input_statement(self, segment);
        verify_split_wrapper(
            &SPLIT_WRAPPER_PARAMS_VERIFIER,
            &PARAMS_VERIFIER,
            &SPEND_SPLIT_WRAPPER_VK,
            &SPLIT_WRAPPER_INNER_KEYS,
            &public_inputs,
            split_bundle,
        )
        .map_err(|err| MalformedOffer::InvalidProof(anyhow::anyhow!(err.to_string())))
    }
}

#[cfg(feature = "proof-verifying")]
#[allow(dead_code)]
fn verify_client_derivation_proof(
    split: &SplitPublicInputs,
    proof: &Proof,
    nullifier: coin_structure::coin::Nullifier,
) -> Result<(), MalformedOffer> {
    let mut statement = vec![Fr::from(0u64)];
    statement.extend(client_derivation_public_transcript_inputs(
        split.public_key,
        nullifier.0.0,
        split.coin_binding_tag,
        split.commitment_sk,
    ));
    CLIENT_DERIVATION_VK
        .verify(&PARAMS_VERIFIER, proof, statement.into_iter())
        .map_err(MalformedOffer::InvalidProof)
}

#[cfg(feature = "proof-verifying")]
#[allow(dead_code)]
fn verify_wallet_attestation_proof(
    pk: coin_structure::coin::PublicKey,
    commitment_sk: Fr,
    proof: &Proof,
) -> Result<(), MalformedOffer> {
    let mut statement = vec![Fr::from(0u64)];
    statement.extend(wallet_attestation_public_transcript_inputs(
        pk,
        commitment_sk,
    ));
    WALLET_ATTESTATION_VK
        .verify(&PARAMS_VERIFIER, proof, statement.into_iter())
        .map_err(MalformedOffer::InvalidProof)
}

/// Mirror of the public-input cells declared by
/// `circuits/wallet_attestation.compact`: cell 0 → `pk`, cell 1 → `commitmentSk`.
#[cfg(feature = "proof-verifying")]
#[allow(dead_code)]
fn wallet_attestation_public_transcript_inputs(
    pk: coin_structure::coin::PublicKey,
    commitment_sk: Fr,
) -> Vec<Fr> {
    let mut inputs = Vec::new();
    extend_ops(
        &mut inputs,
        Cell_write!(
            [Key::Value(0u8.into())],
            false,
            coin_structure::coin::PublicKey,
            pk
        ),
    );
    extend_ops(
        &mut inputs,
        Cell_write!([Key::Value(1u8.into())], false, Fr, commitment_sk),
    );
    inputs
}

#[cfg(feature = "proof-verifying")]
#[allow(dead_code)]
fn client_derivation_public_transcript_inputs(
    pk: coin_structure::coin::PublicKey,
    nullifier: [u8; 32],
    coin_binding_tag: Fr,
    commitment_sk: Fr,
) -> Vec<Fr> {
    let mut inputs = Vec::new();
    extend_ops(
        &mut inputs,
        Cell_write!(
            [Key::Value(0u8.into())],
            false,
            coin_structure::coin::PublicKey,
            pk
        ),
    );
    extend_ops(
        &mut inputs,
        Cell_write!([Key::Value(1u8.into())], false, [u8; 32], nullifier),
    );
    extend_ops(
        &mut inputs,
        Cell_write!([Key::Value(2u8.into())], false, Fr, coin_binding_tag),
    );
    // v3 cell 3 — Poseidon commitment to sk; cross-checked against the
    // attestation's public output.
    extend_ops(
        &mut inputs,
        Cell_write!([Key::Value(3u8.into())], false, Fr, commitment_sk),
    );
    inputs
}

#[cfg(feature = "proof-verifying")]
#[allow(dead_code)]
fn extend_ops<const N: usize>(inputs: &mut Vec<Fr>, ops: [Op<ResultModeVerify, InMemoryDB>; N]) {
    for op in filter_invalid(ops.into_iter()) {
        op.field_repr(inputs);
    }
}

impl<D: DB> Input<(), D> {
    #[instrument]
    pub fn well_formed(&self, _segment: u16) -> Result<(), MalformedOffer> {
        Ok(())
    }
}

impl<D: DB> Output<Proof, D> {
    #[cfg(not(feature = "proof-verifying"))]
    pub fn well_formed(&self, _segment: u16) -> Result<(), MalformedOffer> {
        if let (Some(address), Some(ciphertext)) = (self.contract_address.clone(), &self.ciphertext)
        {
            return Err(MalformedOffer::ContractSentCiphertext {
                address: *address.deref(),
                ciphertext: Box::new(ciphertext.deref().clone()),
            });
        }
        Ok(())
    }

    #[instrument]
    #[cfg(feature = "proof-verifying")]
    pub fn well_formed(&self, segment: u16) -> Result<(), MalformedOffer> {
        if let (Some(address), Some(ciphertext)) = (self.contract_address.clone(), &self.ciphertext)
        {
            return Err(MalformedOffer::ContractSentCiphertext {
                address: *address.deref(),
                ciphertext: Box::new(ciphertext.deref().clone()),
            });
        }
        let mut prog = Vec::new();
        prog.extend::<[Op<_, InMemoryDB>; 17]>(HistoricMerkleTree_insert_hash!(
            [Key::Value(0u8.into())],
            false,
            32,
            [u8; 32],
            self.coin_com
        ));
        match &self.contract_address {
            Some(addr) => prog.extend(Cell_write!(
                [Key::Value(3u8.into())],
                false,
                ContractAddress,
                addr.deref()
            )),
            None => prog.push(Op::Noop { n: CADDR_OP_LEN }),
        }
        prog.extend(Cell_read!([Key::Value(5u8.into())], false, u16));
        prog.extend(Cell_write!(
            [Key::Value(2u8.into())],
            false,
            (Fr, Fr),
            self.value_commitment.0
        ));
        let msg = match &self.ciphertext {
            Some(ciph) => ciphertext_to_field(ciph),
            None => 0.into(),
        };
        let mut statement = vec![msg];
        for op in with_outputs(prog.into_iter(), [segment.into()].into_iter()) {
            op.field_repr(&mut statement);
        }
        OUTPUT_VK
            .verify(&PARAMS_VERIFIER, &self.proof, statement.into_iter())
            .map_err(MalformedOffer::InvalidProof)
    }
}

impl<D: DB> Output<(), D> {
    #[instrument]
    pub fn well_formed(&self, _segment: u16) -> Result<(), MalformedOffer> {
        if let (Some(address), Some(ciphertext)) = (self.contract_address.clone(), &self.ciphertext)
        {
            return Err(MalformedOffer::ContractSentCiphertext {
                address: *address.deref(),
                ciphertext: Box::new(ciphertext.deref().clone()),
            });
        }
        Ok(())
    }
}

impl<D: DB> Transient<Proof, D> {
    pub fn well_formed(&self, segment: u16) -> Result<(), MalformedOffer> {
        self.as_input().well_formed(segment)?;
        self.as_output().well_formed(segment)?;
        Ok(())
    }
}

impl<D: DB> Transient<(), D> {
    pub fn well_formed(&self, segment: u16) -> Result<(), MalformedOffer> {
        self.as_input().well_formed(segment)?;
        self.as_output().well_formed(segment)?;
        Ok(())
    }
}

#[allow(unstable_name_collisions)] // is_sorted method by the same name works the same.
fn offer_well_formed_common<P: Ord + Storable<D>, D: DB>(
    offer: &Offer<P, D>,
    segment: u16,
) -> Result<Pedersen, MalformedOffer> {
    if !offer.inputs.iter().is_sorted()
        || !offer.outputs.iter().is_sorted()
        || !offer.transient.iter().is_sorted()
        || !Vec::from(&offer.deltas)
            .windows(2)
            .all(|slice| slice[0].token_type < slice[1].token_type)
        || !offer.deltas.iter().all(|d| d.value != 0)
    {
        warn!("Zswap offer not in normal form");
        return Err(MalformedOffer::NotNormalized);
    }
    let com_unit: Pedersen = Pedersen(EmbeddedGroupAffine::identity());
    let io_com = offer
        .inputs
        .iter()
        .map(|inp| inp.value_commitment)
        .chain(offer.outputs.iter().map(|inp| -inp.value_commitment))
        .chain(
            offer
                .transient
                .iter()
                .map(|io| io.value_commitment_input - io.value_commitment_output),
        )
        .fold(com_unit, Add::add);
    let deltas_com = offer
        .deltas
        .iter()
        .map(|delta| {
            Pedersen::commit(
                &(delta.token_type, segment),
                &<EmbeddedFr as From<i128>>::from(delta.value),
                &0u64.into(),
            )
        })
        .fold(com_unit, Add::add);
    Ok(io_com - deltas_com)
}

impl<D: DB> Offer<Proof, D> {
    #[instrument(skip(self))]
    pub fn well_formed(&self, segment: u16) -> Result<Pedersen, MalformedOffer> {
        self.inputs
            .iter()
            .try_for_each(|i| i.well_formed(segment))?;
        self.outputs
            .iter()
            .try_for_each(|o| o.well_formed(segment))?;
        self.transient
            .iter()
            .try_for_each(|t| t.well_formed(segment))?;
        offer_well_formed_common(self, segment)
    }
}

impl<D: DB> Offer<(), D> {
    #[instrument(skip(self))]
    pub fn well_formed(&self, segment: u16) -> Result<Pedersen, MalformedOffer> {
        offer_well_formed_common(self, segment)
    }
}

impl<D: DB> Offer<ProofPreimage, D> {
    #[instrument(skip(self))]
    pub fn well_formed(&self, segment: u16) -> Result<Pedersen, MalformedOffer> {
        offer_well_formed_common(self, segment)
    }
}
