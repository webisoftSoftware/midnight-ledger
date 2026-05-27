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
use transient_crypto::merkle_tree::MerkleTreeDigest;
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
// Solution A: the wallet attestation proof no longer travels with split-spend
// bundles; per-spend admission only checks the client-derivation proof and
// the caller-provided registry-root policy.
#[cfg(feature = "proof-verifying")]
const SIGN_VK_RAW: &[u8] = include_bytes!("../static/sign.verifier");
#[cfg(feature = "proof-verifying")]
const SIGN_SPLIT_VK_RAW: &[u8] = include_bytes!("../static/sign-split.verifier");

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
    pub static ref SIGN_VK: VerifierKey = tagged_deserialize(&mut SIGN_VK_RAW.to_vec().as_slice())
        .expect("Zswap Sign VK should be valid");
    pub static ref SIGN_SPLIT_VK: VerifierKey =
        tagged_deserialize(&mut SIGN_SPLIT_VK_RAW.to_vec().as_slice())
            .expect("Zswap Split Sign VK should be valid");
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

/// Admission policy for split-spend registry roots.
///
/// Proof verification is still stateless: the verifier only asks whether the
/// root embedded in the split proof bundle is admissible for this call.
pub trait RegistryRootPolicy {
    fn admits_registry_root(&self, root: MerkleTreeDigest) -> bool;
}

impl<F> RegistryRootPolicy for F
where
    F: Fn(MerkleTreeDigest) -> bool,
{
    fn admits_registry_root(&self, root: MerkleTreeDigest) -> bool {
        self(root)
    }
}

pub struct RejectAllRegistryRootPolicy;

impl RegistryRootPolicy for RejectAllRegistryRootPolicy {
    fn admits_registry_root(&self, _root: MerkleTreeDigest) -> bool {
        false
    }
}

pub struct AcceptAllRegistryRootPolicy;

impl RegistryRootPolicy for AcceptAllRegistryRootPolicy {
    fn admits_registry_root(&self, _root: MerkleTreeDigest) -> bool {
        true
    }
}

fn check_registry_root(
    root: MerkleTreeDigest,
    policy: &dyn RegistryRootPolicy,
) -> Result<(), MalformedOffer> {
    if policy.admits_registry_root(root) {
        Ok(())
    } else {
        Err(MalformedOffer::MalformedSplitProofBundle)
    }
}

impl<D: DB> Input<Proof, D> {
    #[cfg(not(feature = "proof-verifying"))]
    pub fn well_formed(&self, segment: u16) -> Result<(), MalformedOffer> {
        self.well_formed_with_registry_policy(segment, &RejectAllRegistryRootPolicy)
    }

    #[cfg(not(feature = "proof-verifying"))]
    pub fn well_formed_with_registry_policy(
        &self,
        _segment: u16,
        registry_policy: &dyn RegistryRootPolicy,
    ) -> Result<(), MalformedOffer> {
        match ZswapInputProof::decode(&self.proof)
            .map_err(|_| MalformedOffer::MalformedSplitProofBundle)?
        {
            ZswapInputProof::Plain(_) => Ok(()),
            ZswapInputProof::Split(split_bundle) => check_registry_root(
                split_bundle.split_public_inputs.registry_root,
                registry_policy,
            ),
        }
    }

    #[instrument]
    #[cfg(feature = "proof-verifying")]
    pub fn well_formed(&self, segment: u16) -> Result<(), MalformedOffer> {
        self.well_formed_with_registry_policy(segment, &RejectAllRegistryRootPolicy)
    }

    #[instrument(skip(self, registry_policy))]
    #[cfg(feature = "proof-verifying")]
    pub fn well_formed_with_registry_policy(
        &self,
        segment: u16,
        registry_policy: &dyn RegistryRootPolicy,
    ) -> Result<(), MalformedOffer> {
        let input_proof = ZswapInputProof::decode(&self.proof)
            .map_err(|_| MalformedOffer::MalformedSplitProofBundle)?;

        if let ZswapInputProof::Split(split_bundle) = input_proof {
            return self.split_well_formed(segment, &split_bundle, registry_policy);
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
    fn split_well_formed(
        &self,
        segment: u16,
        split_bundle: &SplitProofBundle,
        registry_policy: &dyn RegistryRootPolicy,
    ) -> Result<(), MalformedOffer> {
        let split = &split_bundle.split_public_inputs;
        // Solution A admission chain:
        //   (i)  client-derivation proof — proves the per-spend nullifier and
        //        coin_binding_tag came from a wallet whose `reg_leaf` is a
        //        Merkle-path member rooted at `split.registry_root`. The
        //        client circuit binds `nullifier`, `coinBindingTag` and
        //        `registryRoot` to a single `(sk, r, salt, pk, coin, path)`
        //        witness tuple under Poseidon binding for `C_sk` and
        //        `reg_leaf`.
        //   (ii) registry-root cross-check — `split.registry_root` must be
        //        accepted by the caller-provided policy. Soundness of (i)
        //        without (ii) is vacuous — an attacker could supply any
        //        made-up root.
        //   (iii) spend-split proof — the existing server-side circuit, now
        //        with `publicKey`/`coinCommitment` ledger cells dropped (see
        //        `deps/midnight-ledger/zswap/zswap-split.compact`). Binds the
        //        Zswap merkle membership of the spent coin and value commit.
        verify_client_derivation_proof(
            split,
            &split_bundle.client_derivation_proof,
            self.nullifier,
        )?;
        check_registry_root(split.registry_root, registry_policy)?;

        let mut split_prog = Vec::new();
        split_prog.extend::<[Op<ResultModeGather, InMemoryDB>; 6]>(HistoricMerkleTree_check_root!(
            [Key::Value(0u8.into())],
            false,
            32,
            [u8; 32],
            self.merkle_tree_root
        ));
        // Solution A cell layout (zswap-split.compact ledger declaration order):
        //   0: merkleTree, 1: nullifiers, 2: valueCom, 3: contractAddr,
        //   4: publicKey (kept for signSplitUser), 5: coinBindingTag,
        //   6: segment. The previous `coinCommitment` cell (was 5) is gone.
        split_prog.extend(Cell_write!(
            [Key::Value(5u8.into())],
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
        split_prog.extend(Cell_read!([Key::Value(6u8.into())], false, u16));
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

    pub fn split_registry_root(&self) -> Result<Option<MerkleTreeDigest>, MalformedOffer> {
        match ZswapInputProof::decode(&self.proof)
            .map_err(|_| MalformedOffer::MalformedSplitProofBundle)?
        {
            ZswapInputProof::Plain(_) => Ok(None),
            ZswapInputProof::Split(bundle) => Ok(Some(bundle.split_public_inputs.registry_root)),
        }
    }
}

#[cfg(feature = "proof-verifying")]
fn verify_client_derivation_proof(
    split: &SplitPublicInputs,
    proof: &Proof,
    nullifier: coin_structure::coin::Nullifier,
) -> Result<(), MalformedOffer> {
    let mut statement = vec![Fr::from(0u64)];
    statement.extend(client_derivation_public_transcript_inputs(
        nullifier.0.0,
        split.coin_binding_tag,
        split.registry_root,
    ));
    CLIENT_DERIVATION_VK
        .verify(&PARAMS_VERIFIER, proof, statement.into_iter())
        .map_err(MalformedOffer::InvalidProof)
}

#[cfg(feature = "proof-verifying")]
fn client_derivation_public_transcript_inputs(
    nullifier: [u8; 32],
    coin_binding_tag: Fr,
    registry_root: MerkleTreeDigest,
) -> Vec<Fr> {
    let mut inputs = Vec::new();
    // Solution A `sk_proof.compact` ledger declaration order:
    //   cell 0 → nullifier (Bytes<32>),
    //   cell 1 → coinBindingTag (Field),
    //   cell 2 → registryRoot (MerkleTreeDigest — lowers to a single Field
    //            ledger cell with Field alignment).
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
        Cell_write!([Key::Value(2u8.into())], false, Fr, registry_root.0),
    );
    inputs
}

#[cfg(feature = "proof-verifying")]
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
        self.well_formed_with_registry_policy(segment, &RejectAllRegistryRootPolicy)
    }

    pub fn well_formed_with_registry_policy(
        &self,
        segment: u16,
        registry_policy: &dyn RegistryRootPolicy,
    ) -> Result<(), MalformedOffer> {
        self.as_input()
            .well_formed_with_registry_policy(segment, registry_policy)?;
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
        self.well_formed_with_registry_policy(segment, &RejectAllRegistryRootPolicy)
    }

    #[instrument(skip(self, registry_policy))]
    pub fn well_formed_with_registry_policy(
        &self,
        segment: u16,
        registry_policy: &dyn RegistryRootPolicy,
    ) -> Result<Pedersen, MalformedOffer> {
        self.inputs
            .iter()
            .try_for_each(|i| i.well_formed_with_registry_policy(segment, registry_policy))?;
        self.outputs
            .iter()
            .try_for_each(|o| o.well_formed(segment))?;
        self.transient
            .iter()
            .try_for_each(|t| t.well_formed_with_registry_policy(segment, registry_policy))?;
        offer_well_formed_common(self, segment)
    }

    pub fn split_registry_roots(&self) -> Result<Vec<MerkleTreeDigest>, MalformedOffer> {
        let mut roots = self
            .inputs
            .iter()
            .try_fold(Vec::new(), |mut roots, input| {
                if let Some(root) = input.split_registry_root()? {
                    roots.push(root);
                }
                Ok(roots)
            })?;
        for transient in self.transient.iter() {
            if let Some(root) = transient.as_input().split_registry_root()? {
                roots.push(root);
            }
        }
        Ok(roots)
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
