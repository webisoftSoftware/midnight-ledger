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

use crate::ZSWAP_TREE_HEIGHT;
use crate::error::MalformedOffer;
use base_crypto::hash::HashOutput;
use coin_structure::coin::{
    Commitment, Info as CoinInfo, Nullifier, PublicKey as CoinPublicKey, ShieldedTokenType,
    TokenType, UnshieldedTokenType,
};
use coin_structure::contract::ContractAddress;
use derive_where::derive_where;
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use serde::Serialize;
use serialize::{Deserializable, Serializable, Tagged, tag_enforcement_test};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::ops::{Add, Sub};
use std::sync::Arc;
use storage::Storable;
use storage::arena::Sp;
use storage::arena::{ArenaHash, ArenaKey};
use storage::db::DB;
#[cfg(test)]
use storage::db::InMemoryDB;
use storage::storable::Loader;
use storage::storage::Array;
use transient_crypto::commitment::{Pedersen, PedersenRandomness};
use transient_crypto::curve::{EmbeddedGroupAffine, Fr};
use transient_crypto::encryption;
use transient_crypto::hash::transient_hash;
use transient_crypto::merkle_tree::{MerkleTree, MerkleTreeDigest};
use transient_crypto::proofs::{Proof, ProofPreimage};
use transient_crypto::repr::{FieldRepr, FromFieldRepr};

macro_rules! exptfile {
    ($name:literal, $desc:literal) => {
        (
            concat!("zswap/", midnight_ledger_static::version!(), "/", $name),
            base_crypto::data_provider::hexhash(
                &include_bytes!(concat!("../static/", $name, ".sha256"))
                    .split_at(64)
                    .0,
            ),
            $desc,
        )
    };
}

/// Files provided by Midnight's data provider for Zswap.
pub const ZSWAP_EXPECTED_FILES: &[(&str, [u8; 32], &str)] = &[
    exptfile!(
        "spend.prover",
        "zero-knowledge proving key for Zswap inputs"
    ),
    exptfile!(
        "spend.verifier",
        "zero-knowledge verifying key for Zswap inputs"
    ),
    exptfile!("spend.bzkir", "ZKIR source for Zswap inputs"),
    exptfile!(
        "output.prover",
        "zero-knowledge proving key for Zswap outputs"
    ),
    exptfile!(
        "output.verifier",
        "zero-knowledge verifying key for Zswap outputs"
    ),
    exptfile!("output.bzkir", "ZKIR source for Zswap outputs"),
    exptfile!(
        "sign.prover",
        "zero-knowledge proving key for Zswap signing operations"
    ),
    exptfile!(
        "sign.verifier",
        "zero-knowledge verifying key for Zswap signing operations"
    ),
    exptfile!("sign.bzkir", "ZKIR source for Zswap signing operations"),
    exptfile!(
        "spend-split.prover",
        "zero-knowledge proving key for split Zswap inputs"
    ),
    exptfile!(
        "spend-split.verifier",
        "zero-knowledge verifying key for split Zswap inputs"
    ),
    exptfile!("spend-split.bzkir", "ZKIR source for split Zswap inputs"),
    exptfile!(
        "sign-split.prover",
        "zero-knowledge proving key for split Zswap signing operations"
    ),
    exptfile!(
        "sign-split.verifier",
        "zero-knowledge verifying key for split Zswap signing operations"
    ),
    exptfile!(
        "sign-split.bzkir",
        "ZKIR source for split Zswap signing operations"
    ),
];

pub(crate) const COIN_CIPHERTEXT_LEN: usize = 6;
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Storable)]
#[storable(base)]
pub struct CoinCiphertext {
    pub c: EmbeddedGroupAffine,
    pub ciph: [Fr; COIN_CIPHERTEXT_LEN],
}

impl Tagged for CoinCiphertext {
    fn tag() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("zswap-coin-ciphertext[v1]")
    }
    fn tag_unique_factor() -> String {
        format!("(embedded-group-affine[v1],array(fr-bls,{COIN_CIPHERTEXT_LEN}))")
    }
}
tag_enforcement_test!(CoinCiphertext);

impl Serializable for CoinCiphertext {
    fn serialize(&self, writer: &mut impl std::io::Write) -> Result<(), std::io::Error> {
        <EmbeddedGroupAffine as Serializable>::serialize(&self.c, writer)?;
        // Because this is unversioned we need not send COIN_CIPHERTEXT_LEN
        for elem in self.ciph {
            <Fr as Serializable>::serialize(&elem, writer)?;
        }
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        EmbeddedGroupAffine::serialized_size(&self.c)
            + self
                .ciph
                .iter()
                .map(Serializable::serialized_size)
                .sum::<usize>()
    }
}

impl Deserializable for CoinCiphertext {
    fn deserialize(
        reader: &mut impl std::io::Read,
        recursive_depth: u32,
    ) -> Result<Self, std::io::Error> {
        let c = EmbeddedGroupAffine::deserialize(reader, recursive_depth)?;
        // See note in `transient_crypto::encryption::SecretKey::decrypt` for why the point at
        // infinity is excluded.
        if c.is_infinity() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ciphertext challenge may not be the point at infinity",
            ));
        };
        let ciph = {
            let mut res = [Fr::default(); COIN_CIPHERTEXT_LEN];
            for byte in res.iter_mut() {
                *byte = Fr::deserialize(reader, recursive_depth)?;
            }
            res
        };
        Ok(Self { c, ciph })
    }
}

impl CoinCiphertext {
    pub fn new<R: Rng + CryptoRng + ?Sized>(
        rng: &mut R,
        coin: &CoinInfo,
        pk: encryption::PublicKey,
    ) -> CoinCiphertext {
        pk.encrypt(rng, coin)
            .try_into()
            .expect("ciphertext should have ciphertext length")
    }
}

impl TryFrom<encryption::Ciphertext> for CoinCiphertext {
    type Error = ();

    fn try_from(ciph: encryption::Ciphertext) -> Result<Self, ()> {
        if ciph.ciph.len() != COIN_CIPHERTEXT_LEN {
            return Err(());
        }
        let mut arr = [0.into(); COIN_CIPHERTEXT_LEN];
        arr.copy_from_slice(&ciph.ciph);
        Ok(CoinCiphertext {
            c: ciph.c,
            ciph: arr,
        })
    }
}

impl From<CoinCiphertext> for encryption::Ciphertext {
    fn from(ciph: CoinCiphertext) -> encryption::Ciphertext {
        encryption::Ciphertext {
            c: ciph.c,
            ciph: ciph.ciph.to_vec(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serializable, Serialize)]
#[tag = "zswap-authorized-claim[v3]"]
/// A claim to a specific public key, authorized by the user's private key.
pub struct AuthorizedClaim<P> {
    pub coin: CoinInfo,
    pub recipient: CoinPublicKey,
    pub proof: Arc<P>,
}
tag_enforcement_test!(AuthorizedClaim<()>);

impl<P> AuthorizedClaim<P> {
    pub fn erase_proof(&self) -> AuthorizedClaim<()> {
        AuthorizedClaim {
            coin: self.coin,
            recipient: self.recipient,
            proof: Arc::new(()),
        }
    }
}

#[derive(Storable, Serialize)]
#[derive_where(PartialEq, Eq, PartialOrd, Ord, Hash, Clone; P)]
#[tag = "zswap-input[v2]"]
#[storable(db = D)]
pub struct Input<P: Storable<D>, D: DB> {
    pub nullifier: Nullifier,
    pub value_commitment: Pedersen,
    pub contract_address: Option<Sp<ContractAddress, D>>,
    pub merkle_tree_root: MerkleTreeDigest,
    pub proof: Arc<P>,
}
tag_enforcement_test!(Input<(), InMemoryDB>);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Serializable, Storable)]
#[storable(base)]
#[tag = "zswap-split-public-inputs[v4]"]
pub struct SplitPublicInputs {
    /// Tag binding the client and server split proofs to the same `(coin, pk)`.
    pub coin_binding_tag: Fr,
    /// Solution A: registry-tree historical root the per-spend membership
    /// proof resolves to. The admission verifier checks that this root is in
    /// the registry contract's `HistoricMerkleTree` roots set at the
    /// transaction timestamp. The wallet's `(pk, C_sk)` are no longer
    /// publicly disclosed — the per-spend proof opens its `reg_leaf` to a
    /// blinded preimage under Poseidon binding.
    pub registry_root: MerkleTreeDigest,
}
tag_enforcement_test!(SplitPublicInputs);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitProofBundle {
    pub spend_proof: Proof,
    pub split_public_inputs: SplitPublicInputs,
    /// Per-spend client proof — proves nullifier ↔ coin_binding_tag ↔
    /// `registry_root` over a Merkle-membership opening of `reg_leaf`. No
    /// separate wallet-attestation proof travels with the bundle in
    /// Solution A; registration is a one-off contract tx, not part of every
    /// split-spend.
    pub client_derivation_proof: Proof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZswapInputProof {
    Plain(Proof),
    Split(SplitProofBundle),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MalformedSplitProofBundle;

// v4 magic — bumped from `:v3` so old (per-spend attestation) bundles fail
// closed against the new node verifier. v4 carries only the client proof and
// shrinks the public-input payload to `(coin_binding_tag, registry_root)`.
const SPLIT_PROOF_BUNDLE_MAGIC: &[u8] = b"midnight:zswap-split-proof-bundle:v4";
const SPEND_SPLIT_KEY_LOCATION: &str = "midnight/zswap/spend-split";

fn split_coin_binding_domain() -> Fr {
    let domain = b"midnight:zswap-split-coin[v1]";
    let mut bytes = [0u8; 32];
    bytes[..domain.len()].copy_from_slice(domain);
    Fr::from_le_bytes(&bytes).expect("split coin binding domain fits in Fr")
}

pub fn split_coin_binding_tag(coin: &CoinInfo, pk: CoinPublicKey) -> Fr {
    let mut inputs = vec![split_coin_binding_domain()];
    coin.field_repr(&mut inputs);
    pk.field_repr(&mut inputs);
    transient_hash(&inputs)
}

impl ZswapInputProof {
    pub fn encode(self) -> Proof {
        match self {
            ZswapInputProof::Plain(proof) => proof,
            ZswapInputProof::Split(bundle) => bundle.encode(),
        }
    }

    pub fn decode(proof: &Proof) -> Result<Self, MalformedSplitProofBundle> {
        if !proof.0.starts_with(SPLIT_PROOF_BUNDLE_MAGIC) {
            return Ok(ZswapInputProof::Plain(proof.clone()));
        }
        SplitProofBundle::decode(proof).map(ZswapInputProof::Split)
    }
}

impl SplitProofBundle {
    pub fn new(
        spend_proof: Proof,
        split_public_inputs: SplitPublicInputs,
        client_derivation_proof: Proof,
    ) -> Self {
        SplitProofBundle {
            spend_proof,
            split_public_inputs,
            client_derivation_proof,
        }
    }

    /// v4 wire layout:
    ///   MAGIC ‖
    ///   u32 LE len ‖ spend_proof bytes ‖
    ///   u32 LE len ‖ client_derivation_proof bytes ‖
    ///   coin_binding_tag[32] ‖ registry_root[32]
    pub fn encode(self) -> Proof {
        let mut bytes = Vec::with_capacity(
            SPLIT_PROOF_BUNDLE_MAGIC.len()
                + 4
                + self.spend_proof.0.len()
                + 4
                + self.client_derivation_proof.0.len()
                + 64,
        );
        bytes.extend_from_slice(SPLIT_PROOF_BUNDLE_MAGIC);
        append_len_prefixed(&mut bytes, &self.spend_proof.0);
        append_len_prefixed(&mut bytes, &self.client_derivation_proof.0);
        bytes.extend_from_slice(&self.split_public_inputs.coin_binding_tag.as_le_bytes());
        bytes.extend_from_slice(&self.split_public_inputs.registry_root.0.as_le_bytes());
        Proof(bytes)
    }

    fn decode(proof: &Proof) -> Result<Self, MalformedSplitProofBundle> {
        let mut remaining = proof.0.as_slice();
        remaining = remaining
            .strip_prefix(SPLIT_PROOF_BUNDLE_MAGIC)
            .ok_or(MalformedSplitProofBundle)?;
        let spend_proof = Proof(
            read_len_prefixed(&mut remaining)
                .ok_or(MalformedSplitProofBundle)?
                .to_vec(),
        );
        let client_derivation_proof = Proof(
            read_len_prefixed(&mut remaining)
                .ok_or(MalformedSplitProofBundle)?
                .to_vec(),
        );
        let coin_binding_tag =
            Fr::from_le_bytes(read_exact(&mut remaining, 32).ok_or(MalformedSplitProofBundle)?)
                .ok_or(MalformedSplitProofBundle)?;
        let registry_root = MerkleTreeDigest(
            Fr::from_le_bytes(read_exact(&mut remaining, 32).ok_or(MalformedSplitProofBundle)?)
                .ok_or(MalformedSplitProofBundle)?,
        );
        if !remaining.is_empty() {
            return Err(MalformedSplitProofBundle);
        }
        Ok(SplitProofBundle {
            spend_proof,
            split_public_inputs: SplitPublicInputs {
                coin_binding_tag,
                registry_root,
            },
            client_derivation_proof,
        })
    }
}

#[derive(Clone)]
pub struct SplitInput<D: DB> {
    pub input: Input<ProofPreimage, D>,
    pub split_public_inputs: SplitPublicInputs,
    pub client_derivation_proof: Proof,
}

impl<D: DB> SplitInput<D> {
    pub fn into_preimage(self) -> Input<ProofPreimage, D> {
        self.input
    }

    pub fn into_proved_input(self, spend_proof: Proof) -> Input<Proof, D> {
        let proof = ZswapInputProof::Split(SplitProofBundle::new(
            spend_proof,
            self.split_public_inputs,
            self.client_derivation_proof,
        ))
        .encode();
        Input {
            nullifier: self.input.nullifier,
            value_commitment: self.input.value_commitment,
            contract_address: self.input.contract_address,
            merkle_tree_root: self.input.merkle_tree_root,
            proof: Arc::new(proof),
        }
    }
}

fn append_len_prefixed(bytes: &mut Vec<u8>, value: &[u8]) {
    let len = u32::try_from(value.len()).expect("proof is too large to bundle");
    bytes.extend_from_slice(&len.to_le_bytes());
    bytes.extend_from_slice(value);
}

fn read_len_prefixed<'a>(remaining: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = u32::from_le_bytes(read_exact_array(remaining)?) as usize;
    read_exact(remaining, len)
}

fn read_exact<'a>(remaining: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
    if remaining.len() < len {
        return None;
    }
    let (head, tail) = remaining.split_at(len);
    *remaining = tail;
    Some(head)
}

fn read_exact_array<const N: usize>(remaining: &mut &[u8]) -> Option<[u8; N]> {
    read_exact(remaining, N)?.try_into().ok()
}

impl<P> Debug for AuthorizedClaim<P> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "<claim of {} of token {:?} for recipient {:?}>",
            self.coin.value, self.coin.type_, self.recipient
        )
    }
}

impl<P: Storable<D>, D: DB> Input<P, D> {
    pub fn erase_proof(&self) -> Input<(), D> {
        Input {
            nullifier: self.nullifier,
            value_commitment: self.value_commitment,
            contract_address: self.contract_address.clone(),
            merkle_tree_root: self.merkle_tree_root,
            proof: Arc::new(()),
        }
    }
}

impl<D: DB> Input<ProofPreimage, D> {
    fn public_witness_trailer_len(&self) -> usize {
        if self.proof.key_location.0.as_ref() == SPEND_SPLIT_KEY_LOCATION {
            Nullifier::FIELD_SIZE
        } else {
            0
        }
    }

    fn binding_randomness_index(&self) -> usize {
        self.proof
            .inputs
            .len()
            .checked_sub(self.public_witness_trailer_len() + 1)
            .expect("must have witness to extract from")
    }

    pub fn delta(&self) -> Delta {
        // NOTE: This is tied to the implementation in construct.rs
        // CoinInfo is immediately before rc.
        let inputs = &self.proof.inputs;
        let coin_end = self.binding_randomness_index();
        let coin_start = coin_end
            .checked_sub(CoinInfo::FIELD_SIZE)
            .expect("must have coin info witness to extract from");
        let coin = CoinInfo::from_field_repr(&inputs[coin_start..coin_end])
            .expect("coin info must be correct encoded in input preimage");
        Delta {
            token_type: coin.type_,
            value: coin.value.try_into().unwrap_or(i128::MAX),
        }
    }

    pub fn binding_randomness(&self) -> PedersenRandomness {
        // NOTE: This is tied to the implementation in construct.rs
        // rc should be a single Fr element.
        self.proof.inputs[self.binding_randomness_index()]
            .try_into()
            .expect("extracted binding randomness is invalid")
    }
}

impl<P: Storable<D>, D: DB> Debug for Input<P, D> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match &self.contract_address {
            Some(addr) => write!(
                formatter,
                "<shielded input {:?} for: {:?}>",
                self.nullifier, addr
            ),
            None => write!(formatter, "<shielded input {:?}>", self.nullifier),
        }
    }
}

impl<D: DB> Input<ProofPreimage, D> {
    pub fn segment(&self) -> Option<u16> {
        self.proof
            .public_transcript_outputs
            .iter()
            .copied()
            .last()
            .map(TryInto::<u16>::try_into)
            .transpose()
            .unwrap_or(None)
    }
}

#[derive(Storable, Serialize)]
#[derive_where(PartialEq, Eq, PartialOrd, Ord, Hash, Clone; P)]
#[tag = "zswap-output[v2]"]
#[storable(db = D)]
pub struct Output<P: Storable<D>, D: DB> {
    pub coin_com: Commitment,
    pub value_commitment: Pedersen,
    pub contract_address: Option<Sp<ContractAddress, D>>,
    pub ciphertext: Option<Sp<CoinCiphertext, D>>,
    pub proof: Arc<P>,
}
tag_enforcement_test!(Output<(), InMemoryDB>);

impl<P: Storable<D>, D: DB> Output<P, D> {
    pub fn erase_proof(&self) -> Output<(), D> {
        Output {
            coin_com: self.coin_com,
            value_commitment: self.value_commitment,
            contract_address: self.contract_address.clone(),
            ciphertext: self.ciphertext.clone(),
            proof: Arc::new(()),
        }
    }
}

impl<D: DB> Output<ProofPreimage, D> {
    pub fn delta(&self) -> Delta {
        // NOTE: This is tied to the implementation in construct.rs.
        // Input before last is CoinInfo
        let inputs = &self.proof.inputs;
        let coin = CoinInfo::from_field_repr(
            &inputs[inputs.len() - 1 - CoinInfo::FIELD_SIZE..inputs.len() - 1],
        )
        .expect("coin info must be correct encoded in input preimage");
        Delta {
            token_type: coin.type_,
            value: coin.value.try_into().unwrap_or(i128::MAX).saturating_neg(),
        }
    }

    pub fn binding_randomness(&self) -> PedersenRandomness {
        // NOTE: This is tied to the implementation in construct.rs.
        // rc is the last input, and should be a single Fr element.
        // NOTE: rc negated because output commitments are subtracted
        -PedersenRandomness::try_from(
            *self
                .proof
                .inputs
                .last()
                .expect("must have witness to extract from"),
        )
        .expect("extracted binding randomness is invalid")
    }
    pub fn segment(&self) -> Option<u16> {
        self.proof
            .public_transcript_outputs
            .iter()
            .copied()
            .last()
            .map(TryInto::<u16>::try_into)
            .transpose()
            .unwrap_or(None)
    }
}

impl<P: Storable<D>, D: DB> Debug for Output<P, D> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match &self.contract_address {
            Some(addr) => write!(
                formatter,
                "<shielded output {:?} for: {:?}>",
                self.coin_com, addr
            ),
            None => write!(formatter, "<shielded output {:?}>", self.coin_com),
        }
    }
}

#[derive(Storable, Serialize)]
#[derive_where(PartialOrd, Ord, PartialEq, Eq, Clone; P)]
#[tag = "zswap-transient[v2]"]
#[storable(db = D)]
pub struct Transient<P: Storable<D>, D: DB> {
    pub nullifier: Nullifier,
    pub coin_com: Commitment,
    pub value_commitment_input: Pedersen,
    pub value_commitment_output: Pedersen,
    pub contract_address: Option<Sp<ContractAddress, D>>,
    pub ciphertext: Option<Sp<CoinCiphertext, D>>,
    pub proof_input: Arc<P>,
    pub proof_output: Arc<P>,
}
tag_enforcement_test!(Transient<(), InMemoryDB>);

impl<P: Storable<D>, D: DB> Transient<P, D> {
    pub fn erase_proof(&self) -> Transient<(), D> {
        Transient {
            nullifier: self.nullifier,
            coin_com: self.coin_com,
            value_commitment_input: self.value_commitment_input,
            value_commitment_output: self.value_commitment_output,
            contract_address: self.contract_address.clone(),
            ciphertext: self.ciphertext.clone(),
            proof_input: Arc::new(()),
            proof_output: Arc::new(()),
        }
    }
}

impl<D: DB> Transient<ProofPreimage, D> {
    pub fn binding_randomness(&self) -> PedersenRandomness {
        self.as_input().binding_randomness() + self.as_output().binding_randomness()
    }
    pub fn segment(&self) -> Option<u16> {
        self.as_input().segment()
    }
}

impl<P: Clone + Storable<D>, D: DB> Transient<P, D> {
    pub fn as_input(&self) -> Input<P, D> {
        Input {
            nullifier: self.nullifier,
            value_commitment: self.value_commitment_input,
            contract_address: self.contract_address.clone(),
            merkle_tree_root: MerkleTree::<_>::blank(ZSWAP_TREE_HEIGHT)
                .update_hash(0, self.coin_com.0, ())
                .rehash()
                .root()
                .expect("rehashed tree must have root"),
            proof: self.proof_input.clone(),
        }
    }

    pub fn as_output(&self) -> Output<P, D> {
        Output {
            coin_com: self.coin_com,
            value_commitment: self.value_commitment_output,
            contract_address: self.contract_address.clone(),
            ciphertext: self.ciphertext.clone(),
            proof: self.proof_output.clone(),
        }
    }
}

impl<P: Storable<D>, D: DB> Debug for Transient<P, D> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match self.contract_address.clone() {
            Some(addr) => {
                write!(
                    formatter,
                    "<shielded transient coin {:?} {:?} for: {:?}>",
                    self.coin_com, self.nullifier, addr
                )
            }
            None => write!(
                formatter,
                "<shielded transient coin {:?} {:?}>",
                self.coin_com, self.nullifier
            ),
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serializable, Serialize, Storable)]
#[storable(base)]
#[tag = "zswap-delta"]
pub struct Delta {
    pub token_type: ShieldedTokenType,
    pub value: i128,
}
tag_enforcement_test!(Delta);

#[derive(Storable)]
#[derive_where(PartialEq, Eq, PartialOrd, Ord, Clone; P)]
#[tag = "zswap-offer[v5]"]
#[storable(db = D)]
/// A Zswap offer consists of a potentially unbalanced set of Zswap
/// inputs/outputs.
///
/// All vectors must be sorted to be valid, and `deltas` must be key-unique
/// (i.e. not contain tuples sharing their first element `(a, b)` and `(a, c)`).
/// This is to have a canonical representation while operating on sets and maps.
pub struct Offer<P: Storable<D>, D: DB> {
    /// A set of Inputs
    pub inputs: Array<Input<P, D>, D>,
    /// A set of Outputs
    pub outputs: Array<Output<P, D>, D>,
    /// A set of "transient" Zswap coins: Coins that are created and spent in
    /// the same transaction
    pub transient: Array<Transient<P, D>, D>,
    /// A map from types (coin colors) to the offer value in this type.
    /// A positive value means more coins have been spent, a negative value
    /// means more coins were created.
    pub deltas: Array<Delta, D>,
}
tag_enforcement_test!(Offer<(), InMemoryDB>);

impl<D: DB> Offer<ProofPreimage, D> {
    pub fn binding_randomness(&self) -> PedersenRandomness {
        self.inputs
            .iter()
            .map(|i| i.binding_randomness())
            .chain(self.outputs.iter().map(|o| o.binding_randomness()))
            .chain(self.transient.iter().map(|t| t.binding_randomness()))
            .fold(0.into(), |a, b| a + b)
    }
}

impl<P: Storable<D>, D: DB> Offer<P, D> {
    pub fn erase_proofs(&self) -> Offer<(), D> {
        Offer {
            inputs: self.inputs.iter_deref().map(Input::erase_proof).collect(),
            outputs: self.outputs.iter_deref().map(Output::erase_proof).collect(),
            transient: self
                .transient
                .iter_deref()
                .map(Transient::erase_proof)
                .collect(),
            deltas: self.deltas.clone(),
        }
    }
}

impl<P: Storable<D>, D: DB> Debug for Offer<P, D> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter
            .debug_map()
            .entry(&Symbol("inputs"), &self.inputs)
            .entry(&Symbol("outputs"), &self.outputs)
            .entry(&Symbol("transient"), &self.transient)
            .entry(
                &Symbol("deltas"),
                &self
                    .deltas
                    .iter_deref()
                    .cloned()
                    .map(DebugDelta)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

struct DebugDelta(Delta);

impl Debug for DebugDelta {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{:?} -> {:?}", self.0.token_type, self.0.value)
    }
}

pub fn normalize_deltas<T: Ord, I: Iterator<Item = (T, i128)>>(deltas: I) -> Vec<(T, i128)> {
    let mut new_deltas: Vec<_> = deltas
        .fold(BTreeMap::new(), |mut map, (k, v)| {
            *map.entry(k).or_insert(0) += v;
            map
        })
        .into_iter()
        .collect();
    new_deltas.retain(|(_, v)| *v != 0);
    new_deltas.sort();
    new_deltas
}

impl<P: Clone + Ord + Storable<D>, D: DB> Offer<P, D> {
    pub fn normalize(&mut self) {
        self.inputs = self.inputs.iter_deref().sorted().cloned().collect();
        self.outputs = self.outputs.iter_deref().sorted().cloned().collect();
        self.transient = self.transient.iter_deref().sorted().cloned().collect();
        self.deltas = normalize_deltas(
            self.deltas
                .iter_deref()
                .map(|delta| (delta.token_type, delta.value)),
        )
        .into_iter()
        .map(|(token_type, value)| Delta { token_type, value })
        .collect();
    }

    #[instrument(skip(self, other))]
    pub fn merge(&self, other: &Self) -> Result<Self, MalformedOffer> {
        #[allow(clippy::mutable_key_type)]
        let inputs1: BTreeSet<_> = self.inputs.iter_deref().cloned().collect();
        #[allow(clippy::mutable_key_type)]
        let inputs2: BTreeSet<_> = other.inputs.iter_deref().cloned().collect();
        #[allow(clippy::mutable_key_type)]
        let outputs1: BTreeSet<_> = self.outputs.iter_deref().cloned().collect();
        #[allow(clippy::mutable_key_type)]
        let outputs2: BTreeSet<_> = other.outputs.iter_deref().cloned().collect();
        #[allow(clippy::mutable_key_type)]
        let transient1: BTreeSet<_> = self.transient.iter_deref().cloned().collect();
        #[allow(clippy::mutable_key_type)]
        let transient2: BTreeSet<_> = other.transient.iter_deref().cloned().collect();
        if inputs1.is_disjoint(&inputs2)
            && outputs1.is_disjoint(&outputs2)
            && transient1.is_disjoint(&transient2)
        {
            let mut res = Offer {
                inputs: inputs1.into_iter().chain(inputs2.into_iter()).collect(),
                outputs: outputs1.into_iter().chain(outputs2.into_iter()).collect(),
                transient: transient1
                    .iter()
                    .chain(transient2.iter())
                    .cloned()
                    .collect(),
                deltas: self
                    .deltas
                    .iter_deref()
                    .chain(other.deltas.iter_deref())
                    .cloned()
                    .collect(),
            };
            res.normalize();
            Ok(res)
        } else {
            warn!("overlap in coins attempted to merge");
            Err(MalformedOffer::NonDisjointCoinMerge)
        }
    }
}

struct Symbol(&'static str);

impl Debug for Symbol {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

pub const INPUT_PIS: usize = 68;
pub const INPUT_PROOF_SIZE: usize = 4_832;
pub const CLIENT_DERIVATION_PIS: usize = 36;
pub const OUTPUT_PIS: usize = 77;
pub const OUTPUT_PROOF_SIZE: usize = 4_832;
pub const AUTHORIZED_CLAIM_PIS: usize = 13;
