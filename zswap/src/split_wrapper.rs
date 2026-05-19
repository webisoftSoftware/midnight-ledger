// This file is part of midnight-ledger.
// Copyright (C) 2025 Midnight Foundation
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0

//! Recursive split-spend wrapper support.

use crate::filter_invalid;
use crate::structure::{Input, SplitProofBundle, SplitPublicInputs};
#[cfg(feature = "proof-verifying")]
use base_crypto::fab::AlignedValue;
#[cfg(feature = "proof-verifying")]
use base_crypto::hash::HashOutput;
use coin_structure::coin::PublicKey as CoinPublicKey;
#[cfg(feature = "proof-verifying")]
use coin_structure::coin::{Commitment, Nullifier};
use ff::{Field, PrimeField};
#[cfg(feature = "proof-verifying")]
use group::Group;
use group::GroupEncoding;
#[cfg(feature = "proof-verifying")]
use midnight_circuits::ecc::{
    curves::CircuitCurve,
    foreign::{ForeignEccChip, ForeignEccConfig, nb_foreign_ecc_chip_columns},
};
#[cfg(feature = "proof-verifying")]
use midnight_circuits::field::{
    NativeChip, NativeConfig, NativeGadget,
    decomposition::{
        chip::{P2RDecompositionChip, P2RDecompositionConfig},
        pow2range::Pow2RangeChip,
    },
    foreign::FieldChip,
    native::NB_ARITH_COLS,
};
#[cfg(feature = "proof-verifying")]
use midnight_circuits::hash::poseidon::{
    NB_POSEIDON_ADVICE_COLS, NB_POSEIDON_FIXED_COLS, PoseidonChip, PoseidonConfig, PoseidonState,
};
#[cfg(feature = "proof-verifying")]
use midnight_circuits::instructions::{
    AssertionInstructions, AssignmentInstructions, PublicInputInstructions,
};
#[cfg(feature = "proof-verifying")]
use midnight_circuits::types::{AssignedNative, ComposableChip, Instantiable};
use midnight_circuits::verifier::{Accumulator, BlstrsEmulation, Msm, SelfEmulation};
#[cfg(feature = "proof-verifying")]
use midnight_circuits::verifier::{
    AssignedAccumulator, AssignedVk, VerifierGadget, fixed_base_names,
};
#[cfg(feature = "proof-verifying")]
use midnight_onchain_runtime::ops::{Key, Op};
#[cfg(feature = "proof-verifying")]
use midnight_onchain_runtime::program_fragments::*;
#[cfg(feature = "proof-verifying")]
use midnight_onchain_runtime::result_mode::{ResultModeGather, ResultModeVerify};
#[cfg(feature = "proof-verifying")]
use midnight_onchain_runtime::state::StateValue;
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
#[cfg(feature = "proof-verifying")]
use storage::arena::Sp;
use storage::db::{DB, InMemoryDB};
#[cfg(feature = "proof-verifying")]
use transient_crypto::commitment::Pedersen;
use transient_crypto::curve::Fr;
#[cfg(feature = "proof-verifying")]
use transient_crypto::merkle_tree::MerkleTreeDigest;
#[cfg(feature = "proof-verifying")]
use transient_crypto::proofs::{ParamsProver, ParamsVerifier, TranscriptHash};
use transient_crypto::proofs::{Proof, VerifierKey};
use transient_crypto::repr::FieldRepr;

#[cfg(feature = "proof-verifying")]
use midnight_curves::Bls12;
#[cfg(feature = "proof-verifying")]
use midnight_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Circuit, ConstraintSystem, Error as PlonkError, ProvingKey, VerifyingKey, create_proof,
        keygen_pk, keygen_vk_with_k, prepare,
    },
    poly::{EvaluationDomain, commitment::Guard, kzg::KZGCommitmentScheme},
    transcript::{CircuitTranscript, Transcript},
    utils::SerdeFormat,
};
#[cfg(feature = "proof-verifying")]
use rand::rngs::OsRng;

pub const SPLIT_WRAPPER_K: u8 = 20;

const SPLIT_WRAPPER_BUNDLE_MAGIC: &[u8] = b"midnight:zswap-split-proof-bundle:v4";

type S = BlstrsEmulation;
type F = <S as SelfEmulation>::F;
type C = <S as SelfEmulation>::C;
#[cfg(feature = "proof-verifying")]
type E = <S as SelfEmulation>::Engine;
#[cfg(feature = "proof-verifying")]
type CBase = <C as CircuitCurve>::Base;
#[cfg(feature = "proof-verifying")]
type NG = NativeGadget<F, P2RDecompositionChip<F>, NativeChip<F>>;
#[cfg(feature = "proof-verifying")]
type WrapperConfig = (
    NativeConfig,
    P2RDecompositionConfig,
    ForeignEccConfig<C>,
    PoseidonConfig<F>,
);
#[cfg(feature = "proof-verifying")]
pub type SplitWrapperVerifyingKey = VerifyingKey<F, KZGCommitmentScheme<Bls12>>;
#[cfg(feature = "proof-verifying")]
pub type SplitWrapperProvingKey = ProvingKey<F, KZGCommitmentScheme<Bls12>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitWrapperProofBundle {
    pub wrapper_proof: Proof,
    pub aggregate_accumulator: Vec<u8>,
}

impl SplitWrapperProofBundle {
    pub fn new(wrapper_proof: Proof, aggregate_accumulator: Vec<u8>) -> Self {
        Self {
            wrapper_proof,
            aggregate_accumulator,
        }
    }

    pub fn encode(self) -> Proof {
        let mut bytes = Vec::with_capacity(
            SPLIT_WRAPPER_BUNDLE_MAGIC.len()
                + 4
                + self.wrapper_proof.0.len()
                + 4
                + self.aggregate_accumulator.len(),
        );
        bytes.extend_from_slice(SPLIT_WRAPPER_BUNDLE_MAGIC);
        append_len_prefixed(&mut bytes, &self.wrapper_proof.0);
        append_len_prefixed(&mut bytes, &self.aggregate_accumulator);
        Proof(bytes)
    }

    pub fn decode(proof: &Proof) -> Result<Self, ()> {
        let mut remaining = proof.0.as_slice();
        remaining = remaining
            .strip_prefix(SPLIT_WRAPPER_BUNDLE_MAGIC)
            .ok_or(())?;
        let wrapper_proof = Proof(read_len_prefixed(&mut remaining).ok_or(())?.to_vec());
        let aggregate_accumulator = read_len_prefixed(&mut remaining).ok_or(())?.to_vec();
        if aggregate_accumulator.is_empty() || !remaining.is_empty() {
            return Err(());
        }
        Ok(Self {
            wrapper_proof,
            aggregate_accumulator,
        })
    }

    pub fn is_v4(proof: &Proof) -> bool {
        proof.0.starts_with(SPLIT_WRAPPER_BUNDLE_MAGIC)
    }

    pub fn accumulator(&self) -> Result<Accumulator<S>, io::Error> {
        decode_accumulator(&self.aggregate_accumulator)
    }
}

pub fn encode_accumulator(acc: &Accumulator<S>) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    write_msm(&mut bytes, &acc.lhs())?;
    write_msm(&mut bytes, &acc.rhs())?;
    Ok(bytes)
}

pub fn decode_accumulator(bytes: &[u8]) -> io::Result<Accumulator<S>> {
    let mut reader = bytes;
    let lhs = read_msm(&mut reader)?;
    let rhs = read_msm(&mut reader)?;
    if !reader.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing accumulator bytes",
        ));
    }
    Ok(Accumulator::new(lhs, rhs))
}

fn write_msm(mut writer: impl Write, msm: &Msm<S>) -> io::Result<()> {
    let bases = msm.bases();
    let scalars = msm.scalars();
    if bases.len() != scalars.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed MSM: base/scalar length mismatch",
        ));
    }
    write_u32(&mut writer, bases.len())?;
    for (base, scalar) in bases.iter().zip(scalars.iter()) {
        write_point(&mut writer, *base)?;
        write_field(&mut writer, *scalar)?;
    }

    let fixed = msm.fixed_base_scalars();
    write_u32(&mut writer, fixed.len())?;
    for (name, scalar) in fixed {
        let name = name.as_bytes();
        write_u32(&mut writer, name.len())?;
        writer.write_all(name)?;
        write_field(&mut writer, scalar)?;
    }
    Ok(())
}

fn read_msm(mut reader: impl Read) -> io::Result<Msm<S>> {
    let variable_len = read_u32(&mut reader)?;
    let mut bases = Vec::with_capacity(variable_len);
    let mut scalars = Vec::with_capacity(variable_len);
    for _ in 0..variable_len {
        bases.push(read_point(&mut reader)?);
        scalars.push(read_field(&mut reader)?);
    }

    let fixed_len = read_u32(&mut reader)?;
    let mut fixed = BTreeMap::new();
    for _ in 0..fixed_len {
        let name_len = read_u32(&mut reader)?;
        let mut name = vec![0u8; name_len];
        reader.read_exact(&mut name)?;
        let name = String::from_utf8(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid base name"))?;
        fixed.insert(name, read_field(&mut reader)?);
    }
    Ok(Msm::new(&bases, &scalars, &fixed))
}

fn write_point(mut writer: impl Write, point: C) -> io::Result<()> {
    let affine = <S as SelfEmulation>::G1Affine::from(point);
    writer.write_all(affine.to_bytes().as_ref())
}

fn read_point(mut reader: impl Read) -> io::Result<C> {
    let mut repr = <<S as SelfEmulation>::G1Affine as GroupEncoding>::Repr::default();
    reader.read_exact(repr.as_mut())?;
    let affine: <S as SelfEmulation>::G1Affine =
        Option::from(<S as SelfEmulation>::G1Affine::from_bytes(&repr))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid G1 point"))?;
    Ok(affine.into())
}

fn write_field(mut writer: impl Write, field: F) -> io::Result<()> {
    writer.write_all(field.to_repr().as_ref())
}

fn read_field(mut reader: impl Read) -> io::Result<F> {
    let mut repr = <F as PrimeField>::Repr::default();
    reader.read_exact(repr.as_mut())?;
    Option::from(F::from_repr(repr))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid field element"))
}

fn write_u32(mut writer: impl Write, value: usize) -> io::Result<()> {
    let value = u32::try_from(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "length too large"))?;
    writer.write_all(&value.to_le_bytes())
}

fn read_u32(mut reader: impl Read) -> io::Result<usize> {
    let mut bytes = [0u8; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes) as usize)
}

fn append_len_prefixed(bytes: &mut Vec<u8>, value: &[u8]) {
    let len = u32::try_from(value.len()).expect("proof is too large to bundle");
    bytes.extend_from_slice(&len.to_le_bytes());
    bytes.extend_from_slice(value);
}

fn read_len_prefixed<'a>(remaining: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len_bytes: [u8; 4] = remaining.get(..4)?.try_into().ok()?;
    *remaining = &remaining[4..];
    let len = u32::from_le_bytes(len_bytes) as usize;
    let value = remaining.get(..len)?;
    *remaining = &remaining[len..];
    Some(value)
}

pub fn wrapper_public_inputs<D: DB>(input: &Input<Proof, D>, segment: u16) -> Vec<Fr> {
    let mut inputs = Vec::new();
    inputs.push(input.merkle_tree_root.0);
    input.nullifier.field_repr(&mut inputs);
    segment.field_repr(&mut inputs);
    input.value_commitment.field_repr(&mut inputs);
    inputs
}

#[cfg(feature = "proof-verifying")]
pub fn wallet_attestation_statement(pk: CoinPublicKey, commitment_sk: Fr) -> Vec<Fr> {
    let mut inputs = vec![Fr::from(0u64)];
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

#[cfg(feature = "proof-verifying")]
pub fn client_derivation_statement(
    pk: CoinPublicKey,
    nullifier: [u8; 32],
    coin_binding_tag: Fr,
    commitment_sk: Fr,
) -> Vec<Fr> {
    let mut inputs = vec![Fr::from(0u64)];
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
    extend_ops(
        &mut inputs,
        Cell_write!([Key::Value(3u8.into())], false, Fr, commitment_sk),
    );
    inputs
}

#[cfg(feature = "proof-verifying")]
pub fn spend_split_statement<D: DB>(
    input: &Input<Proof, D>,
    split: &SplitPublicInputs,
    segment: u16,
) -> Vec<Fr> {
    let mut prog = Vec::new();
    prog.extend::<[Op<ResultModeGather, InMemoryDB>; 6]>(HistoricMerkleTree_check_root!(
        [Key::Value(0u8.into())],
        false,
        32,
        [u8; 32],
        input.merkle_tree_root
    ));
    prog.extend(Cell_write!(
        [Key::Value(5u8.into())],
        false,
        [u8; 32],
        split.coin_commitment.0.0
    ));
    prog.extend(Cell_write!(
        [Key::Value(6u8.into())],
        false,
        Fr,
        split.coin_binding_tag
    ));
    prog.extend(Set_insert!(
        [Key::Value(1u8.into())],
        false,
        [u8; 32],
        input.nullifier
    ));
    prog.extend(Cell_read!([Key::Value(7u8.into())], false, u16));
    prog.extend(Cell_write!(
        [Key::Value(2u8.into())],
        false,
        (Fr, Fr),
        input.value_commitment.0
    ));
    let mut statement = vec![Fr::from(0u64)];
    for op in with_outputs(prog.into_iter(), [true.into(), segment.into()].into_iter()) {
        op.field_repr(&mut statement);
    }
    statement
}

#[cfg(feature = "proof-verifying")]
fn extend_ops<const N: usize>(inputs: &mut Vec<Fr>, ops: [Op<ResultModeVerify, InMemoryDB>; N]) {
    for op in filter_invalid(ops.into_iter()) {
        op.field_repr(inputs);
    }
}

#[cfg(feature = "proof-verifying")]
fn with_outputs<
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

pub fn decode_verifier_key(raw: &[u8]) -> Result<VerifierKey, io::Error> {
    serialize::tagged_deserialize(&mut &raw[..])
}

pub fn verifier_fixed_bases(
    name: &str,
    key: &VerifierKey,
) -> Result<BTreeMap<String, C>, Box<dyn std::error::Error + Send + Sync>> {
    let vk = key.midnight_vk()?;
    Ok(midnight_circuits::verifier::fixed_bases::<S>(name, vk.vk()))
}

#[cfg(feature = "proof-verifying")]
#[derive(Clone, Debug)]
struct InnerVerifierCircuit {
    name: &'static str,
    domain: EvaluationDomain<F>,
    cs: ConstraintSystem<F>,
    transcript_repr: F,
}

#[cfg(feature = "proof-verifying")]
#[derive(Clone, Debug)]
struct InnerVerifierKey {
    circuit: InnerVerifierCircuit,
    vk: SplitWrapperVerifyingKey,
}

#[cfg(feature = "proof-verifying")]
#[derive(Clone, Debug)]
pub struct SplitWrapperInnerKeys {
    wallet_attestation: InnerVerifierKey,
    client_derivation: InnerVerifierKey,
    spend_split: InnerVerifierKey,
}

#[cfg(feature = "proof-verifying")]
#[derive(Clone, Debug)]
pub struct SplitWrapperWitness {
    public_inputs: Vec<F>,
    hidden_inputs: Vec<F>,
    wallet_attestation_statement: Vec<F>,
    client_derivation_statement: Vec<F>,
    spend_split_statement: Vec<F>,
    wallet_attestation_proof: Vec<u8>,
    client_derivation_proof: Vec<u8>,
    spend_split_proof: Vec<u8>,
}

#[cfg(feature = "proof-verifying")]
#[derive(Clone, Debug)]
pub struct SplitWrapperCircuit {
    inner_keys: SplitWrapperInnerKeys,
    public_inputs: Value<Vec<F>>,
    hidden_inputs: Value<Vec<F>>,
    wallet_attestation_statement: Value<Vec<F>>,
    client_derivation_statement: Value<Vec<F>>,
    spend_split_statement: Value<Vec<F>>,
    wallet_attestation_proof: Value<Vec<u8>>,
    client_derivation_proof: Value<Vec<u8>>,
    spend_split_proof: Value<Vec<u8>>,
}

#[cfg(feature = "proof-verifying")]
#[derive(Clone, Copy, Debug)]
enum StatementSlot {
    Fixed(F),
    Public(usize),
    Hidden(usize),
}

#[cfg(feature = "proof-verifying")]
#[derive(Clone, Debug)]
struct StatementTemplates {
    wallet_attestation: Vec<StatementSlot>,
    client_derivation: Vec<StatementSlot>,
    spend_split: Vec<StatementSlot>,
}

#[cfg(feature = "proof-verifying")]
#[derive(Clone)]
struct TemplateValues {
    merkle_tree_root: MerkleTreeDigest,
    nullifier: Nullifier,
    segment: u16,
    value_commitment: Pedersen,
    public_key: CoinPublicKey,
    coin_commitment: Commitment,
    coin_binding_tag: Fr,
    commitment_sk: Fr,
}

#[cfg(feature = "proof-verifying")]
const PUBLIC_ROOT: usize = 0;
#[cfg(feature = "proof-verifying")]
const PUBLIC_NULLIFIER: usize = 1;
#[cfg(feature = "proof-verifying")]
const PUBLIC_SEGMENT: usize = 3;
#[cfg(feature = "proof-verifying")]
const PUBLIC_VALUE_COMMITMENT: usize = 4;
#[cfg(feature = "proof-verifying")]
const PUBLIC_INPUTS_LEN: usize = 6;

#[cfg(feature = "proof-verifying")]
const HIDDEN_PUBLIC_KEY: usize = 0;
#[cfg(feature = "proof-verifying")]
const HIDDEN_COIN_COMMITMENT: usize = 2;
#[cfg(feature = "proof-verifying")]
const HIDDEN_COIN_BINDING_TAG: usize = 4;
#[cfg(feature = "proof-verifying")]
const HIDDEN_COMMITMENT_SK: usize = 5;
#[cfg(feature = "proof-verifying")]
const HIDDEN_INPUTS_LEN: usize = 6;

#[cfg(feature = "proof-verifying")]
fn configure_split_wrapper_circuit(meta: &mut ConstraintSystem<F>) -> WrapperConfig {
    let nb_advice_cols = nb_foreign_ecc_chip_columns::<F, C, C, NG>();
    let nb_fixed_cols = NB_ARITH_COLS + 4;

    let advice_columns: Vec<_> = (0..nb_advice_cols).map(|_| meta.advice_column()).collect();
    let fixed_columns: Vec<_> = (0..nb_fixed_cols).map(|_| meta.fixed_column()).collect();
    let committed_instance_column = meta.instance_column();
    let instance_column = meta.instance_column();

    let native_config = NativeChip::configure(
        meta,
        &(
            advice_columns[..NB_ARITH_COLS].try_into().unwrap(),
            fixed_columns[..NB_ARITH_COLS + 4].try_into().unwrap(),
            [committed_instance_column, instance_column],
        ),
    );
    let core_decomp_config = {
        let pow2_config = Pow2RangeChip::configure(meta, &advice_columns[1..NB_ARITH_COLS]);
        P2RDecompositionChip::configure(meta, &(native_config.clone(), pow2_config))
    };

    let base_config = FieldChip::<F, CBase, C, NG>::configure(meta, &advice_columns);
    let curve_config =
        ForeignEccChip::<F, C, C, NG, NG>::configure(meta, &base_config, &advice_columns);

    let poseidon_config = PoseidonChip::configure(
        meta,
        &(
            advice_columns[..NB_POSEIDON_ADVICE_COLS]
                .try_into()
                .unwrap(),
            fixed_columns[..NB_POSEIDON_FIXED_COLS].try_into().unwrap(),
        ),
    );

    (
        native_config,
        core_decomp_config,
        curve_config,
        poseidon_config,
    )
}

#[cfg(feature = "proof-verifying")]
impl Circuit<F> for SplitWrapperCircuit {
    type Config = WrapperConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            inner_keys: self.inner_keys.clone(),
            public_inputs: Value::unknown(),
            hidden_inputs: Value::unknown(),
            wallet_attestation_statement: Value::unknown(),
            client_derivation_statement: Value::unknown(),
            spend_split_statement: Value::unknown(),
            wallet_attestation_proof: Value::unknown(),
            client_derivation_proof: Value::unknown(),
            spend_split_proof: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        configure_split_wrapper_circuit(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), PlonkError> {
        let native_chip = <NativeChip<F> as ComposableChip<F>>::new(&config.0, &());
        let core_decomp_chip =
            P2RDecompositionChip::new(&config.1, &(SPLIT_WRAPPER_K as usize - 1));
        let scalar_chip = NativeGadget::new(core_decomp_chip.clone(), native_chip.clone());
        let curve_chip = ForeignEccChip::new(&config.2, &scalar_chip, &scalar_chip, OsRng);
        let poseidon_chip = PoseidonChip::new(&config.3, &native_chip);
        let verifier_chip = VerifierGadget::new(&curve_chip, &scalar_chip, &poseidon_chip);

        let wallet_vk = assign_inner_vk(
            &verifier_chip,
            &mut layouter,
            &self.inner_keys.wallet_attestation.circuit,
        )?;
        let client_vk = assign_inner_vk(
            &verifier_chip,
            &mut layouter,
            &self.inner_keys.client_derivation.circuit,
        )?;
        let spend_vk = assign_inner_vk(
            &verifier_chip,
            &mut layouter,
            &self.inner_keys.spend_split.circuit,
        )?;

        let templates = statement_templates();
        let public_inputs = assign_public_vec(
            &scalar_chip,
            &mut layouter,
            self.public_inputs.clone(),
            PUBLIC_INPUTS_LEN,
        )?;
        let hidden_inputs = assign_private_vec(
            &scalar_chip,
            &mut layouter,
            self.hidden_inputs.clone(),
            HIDDEN_INPUTS_LEN,
        )?;

        let wallet_statement = assign_private_vec(
            &scalar_chip,
            &mut layouter,
            self.wallet_attestation_statement.clone(),
            templates.wallet_attestation.len(),
        )?;
        constrain_statement_template(
            &scalar_chip,
            &mut layouter,
            &wallet_statement,
            &templates.wallet_attestation,
            &public_inputs,
            &hidden_inputs,
        )?;

        let client_statement = assign_private_vec(
            &scalar_chip,
            &mut layouter,
            self.client_derivation_statement.clone(),
            templates.client_derivation.len(),
        )?;
        constrain_statement_template(
            &scalar_chip,
            &mut layouter,
            &client_statement,
            &templates.client_derivation,
            &public_inputs,
            &hidden_inputs,
        )?;

        let spend_statement = assign_private_vec(
            &scalar_chip,
            &mut layouter,
            self.spend_split_statement.clone(),
            templates.spend_split.len(),
        )?;
        constrain_statement_template(
            &scalar_chip,
            &mut layouter,
            &spend_statement,
            &templates.spend_split,
            &public_inputs,
            &hidden_inputs,
        )?;

        let id_point: <S as SelfEmulation>::AssignedPoint =
            curve_chip.assign_fixed(&mut layouter, C::identity())?;
        let mut wallet_acc = verifier_chip.prepare(
            &mut layouter,
            &wallet_vk,
            &[("com_instance", id_point.clone())],
            &[&wallet_statement],
            self.wallet_attestation_proof.clone(),
        )?;
        wallet_acc.collapse(&mut layouter, &curve_chip, &scalar_chip)?;

        let mut client_acc = verifier_chip.prepare(
            &mut layouter,
            &client_vk,
            &[("com_instance", id_point.clone())],
            &[&client_statement],
            self.client_derivation_proof.clone(),
        )?;
        client_acc.collapse(&mut layouter, &curve_chip, &scalar_chip)?;

        let mut spend_acc = verifier_chip.prepare(
            &mut layouter,
            &spend_vk,
            &[("com_instance", id_point)],
            &[&spend_statement],
            self.spend_split_proof.clone(),
        )?;
        spend_acc.collapse(&mut layouter, &curve_chip, &scalar_chip)?;

        let mut aggregate_acc = AssignedAccumulator::<S>::accumulate(
            &mut layouter,
            &verifier_chip,
            &scalar_chip,
            &poseidon_chip,
            &[wallet_acc, client_acc, spend_acc],
        )?;
        aggregate_acc.collapse(&mut layouter, &curve_chip, &scalar_chip)?;
        verifier_chip.constrain_as_public_input(&mut layouter, &aggregate_acc)?;

        core_decomp_chip.load(&mut layouter)
    }
}

#[cfg(feature = "proof-verifying")]
fn assign_inner_vk(
    verifier_chip: &VerifierGadget<S>,
    layouter: &mut impl Layouter<F>,
    inner: &InnerVerifierCircuit,
) -> Result<AssignedVk<S>, PlonkError> {
    verifier_chip.assign_vk_as_public_input(
        layouter,
        inner.name,
        &inner.domain,
        &inner.cs,
        Value::known(inner.transcript_repr),
    )
}

#[cfg(feature = "proof-verifying")]
fn assign_private_vec(
    scalar_chip: &NG,
    layouter: &mut impl Layouter<F>,
    values: Value<Vec<F>>,
    len: usize,
) -> Result<Vec<AssignedNative<F>>, PlonkError> {
    let values = (0..len)
        .map(|i| values.as_ref().map(move |values| values[i]))
        .collect::<Vec<_>>();
    scalar_chip.assign_many(layouter, &values)
}

#[cfg(feature = "proof-verifying")]
fn assign_public_vec(
    scalar_chip: &NG,
    layouter: &mut impl Layouter<F>,
    values: Value<Vec<F>>,
    len: usize,
) -> Result<Vec<AssignedNative<F>>, PlonkError> {
    (0..len)
        .map(|i| scalar_chip.assign_as_public_input(layouter, values.as_ref().map(move |v| v[i])))
        .collect()
}

#[cfg(feature = "proof-verifying")]
fn constrain_statement_template(
    scalar_chip: &NG,
    layouter: &mut impl Layouter<F>,
    assigned_statement: &[AssignedNative<F>],
    template: &[StatementSlot],
    public_inputs: &[AssignedNative<F>],
    hidden_inputs: &[AssignedNative<F>],
) -> Result<(), PlonkError> {
    for (assigned, slot) in assigned_statement.iter().zip(template) {
        match slot {
            StatementSlot::Fixed(value) => {
                scalar_chip.assert_equal_to_fixed(layouter, assigned, *value)?;
            }
            StatementSlot::Public(index) => {
                scalar_chip.assert_equal(layouter, assigned, &public_inputs[*index])?;
            }
            StatementSlot::Hidden(index) => {
                scalar_chip.assert_equal(layouter, assigned, &hidden_inputs[*index])?;
            }
        }
    }
    Ok(())
}

#[cfg(feature = "proof-verifying")]
pub fn split_wrapper_inner_keys(
    wallet_attestation: &VerifierKey,
    client_derivation: &VerifierKey,
    spend_split: &VerifierKey,
) -> Result<SplitWrapperInnerKeys, Box<dyn std::error::Error + Send + Sync>> {
    Ok(SplitWrapperInnerKeys {
        wallet_attestation: inner_key("wallet_attestation_vk", wallet_attestation)?,
        client_derivation: inner_key("client_derivation_vk", client_derivation)?,
        spend_split: inner_key("spend_split_vk", spend_split)?,
    })
}

#[cfg(feature = "proof-verifying")]
fn inner_key(
    name: &'static str,
    key: &VerifierKey,
) -> Result<InnerVerifierKey, Box<dyn std::error::Error + Send + Sync>> {
    let midnight_vk = key.midnight_vk()?;
    let vk = midnight_vk.vk().clone();
    Ok(InnerVerifierKey {
        circuit: InnerVerifierCircuit {
            name,
            domain: vk.get_domain().clone(),
            cs: vk.cs().clone(),
            transcript_repr: vk.transcript_repr(),
        },
        vk,
    })
}

#[cfg(feature = "proof-verifying")]
impl SplitWrapperWitness {
    pub fn from_split_bundle<D: DB>(
        input: &Input<Proof, D>,
        segment: u16,
        split_bundle: &SplitProofBundle,
    ) -> Result<Self, PlonkError> {
        let split = &split_bundle.split_public_inputs;
        let public_inputs = frs_to_native(wrapper_public_inputs(input, segment));
        if public_inputs.len() != PUBLIC_INPUTS_LEN {
            return Err(PlonkError::Synthesis(
                "unexpected split wrapper public input length".into(),
            ));
        }
        let hidden_inputs = hidden_inputs(split);
        if hidden_inputs.len() != HIDDEN_INPUTS_LEN {
            return Err(PlonkError::Synthesis(
                "unexpected split wrapper hidden input length".into(),
            ));
        }
        Ok(Self {
            public_inputs,
            hidden_inputs,
            wallet_attestation_statement: frs_to_native(wallet_attestation_statement(
                split.public_key,
                split.commitment_sk,
            )),
            client_derivation_statement: frs_to_native(client_derivation_statement(
                split.public_key,
                input.nullifier.0.0,
                split.coin_binding_tag,
                split.commitment_sk,
            )),
            spend_split_statement: frs_to_native(spend_split_statement(input, split, segment)),
            wallet_attestation_proof: split_bundle.attestation_proof.0.clone(),
            client_derivation_proof: split_bundle.client_derivation_proof.0.clone(),
            spend_split_proof: split_bundle.spend_proof.0.clone(),
        })
    }
}

#[cfg(feature = "proof-verifying")]
impl SplitWrapperCircuit {
    pub fn without_witnesses_for_keys(inner_keys: SplitWrapperInnerKeys) -> Self {
        Self {
            inner_keys,
            public_inputs: Value::unknown(),
            hidden_inputs: Value::unknown(),
            wallet_attestation_statement: Value::unknown(),
            client_derivation_statement: Value::unknown(),
            spend_split_statement: Value::unknown(),
            wallet_attestation_proof: Value::unknown(),
            client_derivation_proof: Value::unknown(),
            spend_split_proof: Value::unknown(),
        }
    }

    pub fn with_witness(inner_keys: SplitWrapperInnerKeys, witness: &SplitWrapperWitness) -> Self {
        Self {
            inner_keys,
            public_inputs: Value::known(witness.public_inputs.clone()),
            hidden_inputs: Value::known(witness.hidden_inputs.clone()),
            wallet_attestation_statement: Value::known(
                witness.wallet_attestation_statement.clone(),
            ),
            client_derivation_statement: Value::known(witness.client_derivation_statement.clone()),
            spend_split_statement: Value::known(witness.spend_split_statement.clone()),
            wallet_attestation_proof: Value::known(witness.wallet_attestation_proof.clone()),
            client_derivation_proof: Value::known(witness.client_derivation_proof.clone()),
            spend_split_proof: Value::known(witness.spend_split_proof.clone()),
        }
    }
}

#[cfg(feature = "proof-verifying")]
pub fn keygen_split_wrapper(
    params: &ParamsProver,
    inner_keys: &SplitWrapperInnerKeys,
) -> Result<(SplitWrapperProvingKey, SplitWrapperVerifyingKey), PlonkError> {
    let circuit = SplitWrapperCircuit::without_witnesses_for_keys(inner_keys.clone());
    let vk = keygen_vk_with_k(params.as_ref(), &circuit, SPLIT_WRAPPER_K.into())?;
    let pk = keygen_pk(vk.clone(), &circuit)?;
    Ok((pk, vk))
}

#[cfg(feature = "proof-verifying")]
pub fn read_split_wrapper_proving_key(raw: &[u8]) -> io::Result<SplitWrapperProvingKey> {
    SplitWrapperProvingKey::read::<_, SplitWrapperCircuit>(
        &mut &raw[..],
        SerdeFormat::RawBytesUnchecked,
        (),
    )
}

#[cfg(feature = "proof-verifying")]
pub fn read_split_wrapper_verifying_key(raw: &[u8]) -> io::Result<SplitWrapperVerifyingKey> {
    SplitWrapperVerifyingKey::read::<_, SplitWrapperCircuit>(
        &mut &raw[..],
        SerdeFormat::RawBytesUnchecked,
        (),
    )
}

#[cfg(feature = "proof-verifying")]
pub fn write_split_wrapper_proving_key(
    proving_key: &SplitWrapperProvingKey,
    mut writer: impl Write,
) -> io::Result<()> {
    proving_key.write(&mut writer, SerdeFormat::RawBytesUnchecked)
}

#[cfg(feature = "proof-verifying")]
pub fn write_split_wrapper_verifying_key(
    verifying_key: &SplitWrapperVerifyingKey,
    mut writer: impl Write,
) -> io::Result<()> {
    verifying_key.write(&mut writer, SerdeFormat::RawBytesUnchecked)
}

#[cfg(feature = "proof-verifying")]
pub fn prove_split_wrapper(
    params: &ParamsProver,
    inner_params: &ParamsVerifier,
    proving_key: &SplitWrapperProvingKey,
    inner_keys: &SplitWrapperInnerKeys,
    witness: &SplitWrapperWitness,
    rng: impl rand::RngCore + rand::CryptoRng,
) -> Result<SplitWrapperProofBundle, PlonkError> {
    let aggregate_acc = aggregate_accumulator(inner_keys, witness)?;
    let fixed_bases = aggregate_fixed_bases(inner_keys);
    let tau = inner_params.tau_in_g2().map_err(PlonkError::Transcript)?;
    // VerifierGadget uses Poseidon Fiat-Shamir. Current ledger v3 proofs use
    // the transient-crypto Blake2b transcript, so fail here instead of
    // returning a wrapper proof the node cannot verify.
    if !aggregate_acc.check(&tau, &fixed_bases) {
        return Err(PlonkError::Synthesis(
            "inner split proofs are not valid under the recursive Poseidon transcript".into(),
        ));
    }
    let public_inputs =
        wrapper_verification_statement(inner_keys, &witness.public_inputs, &aggregate_acc);
    let circuit = SplitWrapperCircuit::with_witness(inner_keys.clone(), witness);
    let mut transcript = CircuitTranscript::<TranscriptHash>::init();
    create_proof::<F, KZGCommitmentScheme<E>, CircuitTranscript<TranscriptHash>, _>(
        params.as_ref(),
        proving_key,
        &[circuit],
        1,
        &[&[&[], &public_inputs]],
        rng,
        &mut transcript,
    )?;
    let wrapper_proof = Proof(transcript.finalize());
    verify_split_wrapper_proof(
        &params.as_verifier(),
        proving_key.get_vk(),
        inner_keys,
        &witness.public_inputs,
        &aggregate_acc,
        &wrapper_proof,
    )
    .map_err(|err| {
        PlonkError::Synthesis(format!("split wrapper self verification failed: {err}").into())
    })?;
    Ok(SplitWrapperProofBundle::new(
        wrapper_proof,
        encode_accumulator(&aggregate_acc).map_err(PlonkError::Transcript)?,
    ))
}

#[cfg(feature = "proof-verifying")]
pub fn verify_split_wrapper(
    wrapper_params: &ParamsVerifier,
    inner_params: &ParamsVerifier,
    verifying_key: &SplitWrapperVerifyingKey,
    inner_keys: &SplitWrapperInnerKeys,
    input_public_inputs: &[F],
    bundle: &SplitWrapperProofBundle,
) -> Result<(), PlonkError> {
    let aggregate_acc = bundle.accumulator().map_err(PlonkError::Transcript)?;
    verify_split_wrapper_proof(
        wrapper_params,
        verifying_key,
        inner_keys,
        input_public_inputs,
        &aggregate_acc,
        &bundle.wrapper_proof,
    )?;
    let fixed_bases = aggregate_fixed_bases(inner_keys);
    let tau = inner_params.tau_in_g2().map_err(PlonkError::Transcript)?;
    if !aggregate_acc.check(&tau, &fixed_bases) {
        return Err(PlonkError::Synthesis(
            "invalid split wrapper aggregate accumulator".into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "proof-verifying")]
fn verify_split_wrapper_proof(
    wrapper_params: &ParamsVerifier,
    verifying_key: &SplitWrapperVerifyingKey,
    inner_keys: &SplitWrapperInnerKeys,
    input_public_inputs: &[F],
    aggregate_acc: &Accumulator<S>,
    wrapper_proof: &Proof,
) -> Result<(), PlonkError> {
    let public_inputs =
        wrapper_verification_statement(inner_keys, input_public_inputs, aggregate_acc);
    let mut transcript = CircuitTranscript::<TranscriptHash>::init_from_bytes(&wrapper_proof.0);
    let guard = prepare::<F, KZGCommitmentScheme<E>, CircuitTranscript<TranscriptHash>>(
        verifying_key,
        &[&[C::identity()]],
        &[&[&public_inputs]],
        &mut transcript,
    )?;
    transcript.assert_empty().map_err(|_| PlonkError::Opening)?;
    guard
        .verify(wrapper_params.as_kzg())
        .map_err(|_| PlonkError::Opening)
}

#[cfg(feature = "proof-verifying")]
pub fn wrapper_public_input_statement<D: DB>(input: &Input<Proof, D>, segment: u16) -> Vec<F> {
    frs_to_native(wrapper_public_inputs(input, segment))
}

#[cfg(feature = "proof-verifying")]
fn wrapper_verification_statement(
    inner_keys: &SplitWrapperInnerKeys,
    public_inputs: &[F],
    aggregate_acc: &Accumulator<S>,
) -> Vec<F> {
    [
        vec![
            inner_keys.wallet_attestation.circuit.transcript_repr,
            inner_keys.client_derivation.circuit.transcript_repr,
            inner_keys.spend_split.circuit.transcript_repr,
        ],
        public_inputs.to_vec(),
        AssignedAccumulator::<S>::as_public_input(aggregate_acc),
    ]
    .concat()
}

#[cfg(feature = "proof-verifying")]
fn aggregate_accumulator(
    inner_keys: &SplitWrapperInnerKeys,
    witness: &SplitWrapperWitness,
) -> Result<Accumulator<S>, PlonkError> {
    let mut accs = vec![
        inner_proof_accumulator(
            &inner_keys.wallet_attestation,
            &witness.wallet_attestation_statement,
            &witness.wallet_attestation_proof,
        )?,
        inner_proof_accumulator(
            &inner_keys.client_derivation,
            &witness.client_derivation_statement,
            &witness.client_derivation_proof,
        )?,
        inner_proof_accumulator(
            &inner_keys.spend_split,
            &witness.spend_split_statement,
            &witness.spend_split_proof,
        )?,
    ];
    for acc in &mut accs {
        acc.collapse();
    }
    let mut aggregate = Accumulator::accumulate(&accs);
    aggregate.collapse();
    Ok(aggregate)
}

#[cfg(feature = "proof-verifying")]
fn inner_proof_accumulator(
    inner_key: &InnerVerifierKey,
    statement: &[F],
    proof: &[u8],
) -> Result<Accumulator<S>, PlonkError> {
    let mut transcript = CircuitTranscript::<PoseidonState<F>>::init_from_bytes(proof);
    let dual_msm = prepare::<F, KZGCommitmentScheme<E>, CircuitTranscript<PoseidonState<F>>>(
        &inner_key.vk,
        &[&[C::identity()]],
        &[&[statement]],
        &mut transcript,
    )?;
    transcript.assert_empty().map_err(|_| PlonkError::Opening)?;
    let mut acc: Accumulator<S> = dual_msm.into();
    acc.extract_fixed_bases(&inner_fixed_bases(inner_key));
    Ok(acc)
}

#[cfg(feature = "proof-verifying")]
fn inner_fixed_bases(inner_key: &InnerVerifierKey) -> BTreeMap<String, C> {
    let mut fixed_bases = BTreeMap::new();
    fixed_bases.insert(String::from("com_instance"), C::identity());
    fixed_bases.extend(midnight_circuits::verifier::fixed_bases::<S>(
        inner_key.circuit.name,
        &inner_key.vk,
    ));
    fixed_bases
}

#[cfg(feature = "proof-verifying")]
fn aggregate_fixed_bases(inner_keys: &SplitWrapperInnerKeys) -> BTreeMap<String, C> {
    let mut fixed_bases = BTreeMap::new();
    fixed_bases.extend(inner_fixed_bases(&inner_keys.wallet_attestation));
    fixed_bases.extend(inner_fixed_bases(&inner_keys.client_derivation));
    fixed_bases.extend(inner_fixed_bases(&inner_keys.spend_split));
    fixed_bases
}

#[cfg(feature = "proof-verifying")]
fn hidden_inputs(split: &SplitPublicInputs) -> Vec<F> {
    let mut values = Vec::with_capacity(HIDDEN_INPUTS_LEN);
    split.public_key.field_repr(&mut values);
    split.coin_commitment.field_repr(&mut values);
    split.coin_binding_tag.field_repr(&mut values);
    split.commitment_sk.field_repr(&mut values);
    frs_to_native(values)
}

#[cfg(feature = "proof-verifying")]
fn statement_templates() -> StatementTemplates {
    let base = template_values();
    StatementTemplates {
        wallet_attestation: template_for(
            wallet_statement_from_values,
            &base,
            &[
                (changed_public_key, hidden_range(HIDDEN_PUBLIC_KEY, 2)),
                (changed_commitment_sk, hidden_range(HIDDEN_COMMITMENT_SK, 1)),
            ],
        ),
        client_derivation: template_for(
            client_statement_from_values,
            &base,
            &[
                (changed_public_key, hidden_range(HIDDEN_PUBLIC_KEY, 2)),
                (changed_nullifier, public_range(PUBLIC_NULLIFIER, 2)),
                (
                    changed_coin_binding_tag,
                    hidden_range(HIDDEN_COIN_BINDING_TAG, 1),
                ),
                (changed_commitment_sk, hidden_range(HIDDEN_COMMITMENT_SK, 1)),
            ],
        ),
        spend_split: template_for(
            spend_statement_from_values,
            &base,
            &[
                (changed_root, public_range(PUBLIC_ROOT, 1)),
                (
                    changed_coin_commitment,
                    hidden_range(HIDDEN_COIN_COMMITMENT, 2),
                ),
                (
                    changed_coin_binding_tag,
                    hidden_range(HIDDEN_COIN_BINDING_TAG, 1),
                ),
                (changed_nullifier, public_range(PUBLIC_NULLIFIER, 2)),
                (changed_segment, public_range(PUBLIC_SEGMENT, 1)),
                (
                    changed_value_commitment,
                    public_range(PUBLIC_VALUE_COMMITMENT, 2),
                ),
            ],
        ),
    }
}

#[cfg(feature = "proof-verifying")]
type TemplateBuilder = fn(&TemplateValues) -> Vec<Fr>;
#[cfg(feature = "proof-verifying")]
type TemplateChanger = fn(&mut TemplateValues);

#[cfg(feature = "proof-verifying")]
fn template_for(
    build: TemplateBuilder,
    base: &TemplateValues,
    variables: &[(TemplateChanger, Vec<StatementSlot>)],
) -> Vec<StatementSlot> {
    let baseline = frs_to_native(build(base));
    let mut slots = baseline
        .iter()
        .copied()
        .map(StatementSlot::Fixed)
        .collect::<Vec<_>>();
    for (change, variable_slots) in variables {
        let mut changed_values = base.clone();
        change(&mut changed_values);
        let changed = frs_to_native(build(&changed_values));
        let diffs = baseline
            .iter()
            .zip(&changed)
            .enumerate()
            .filter_map(|(index, (before, after))| (before != after).then_some(index))
            .collect::<Vec<_>>();
        assert_eq!(
            diffs.len(),
            variable_slots.len(),
            "split wrapper statement template variable changed an unexpected number of fields",
        );
        for (index, slot) in diffs.into_iter().zip(variable_slots.iter().copied()) {
            slots[index] = slot;
        }
    }
    slots
}

#[cfg(feature = "proof-verifying")]
fn public_range(start: usize, len: usize) -> Vec<StatementSlot> {
    (start..start + len).map(StatementSlot::Public).collect()
}

#[cfg(feature = "proof-verifying")]
fn hidden_range(start: usize, len: usize) -> Vec<StatementSlot> {
    (start..start + len).map(StatementSlot::Hidden).collect()
}

#[cfg(feature = "proof-verifying")]
fn template_values() -> TemplateValues {
    TemplateValues {
        merkle_tree_root: MerkleTreeDigest(Fr::from(11u64)),
        nullifier: Nullifier(HashOutput([12u8; 32])),
        segment: 13,
        value_commitment: Pedersen::from(transient_crypto::curve::EmbeddedFr::from(14u64)),
        public_key: CoinPublicKey(HashOutput([15u8; 32])),
        coin_commitment: Commitment(HashOutput([16u8; 32])),
        coin_binding_tag: Fr::from(17u64),
        commitment_sk: Fr::from(18u64),
    }
}

#[cfg(feature = "proof-verifying")]
fn changed_root(values: &mut TemplateValues) {
    values.merkle_tree_root = MerkleTreeDigest(Fr::from(101u64));
}

#[cfg(feature = "proof-verifying")]
fn changed_nullifier(values: &mut TemplateValues) {
    values.nullifier = Nullifier(HashOutput([102u8; 32]));
}

#[cfg(feature = "proof-verifying")]
fn changed_segment(values: &mut TemplateValues) {
    values.segment = 103;
}

#[cfg(feature = "proof-verifying")]
fn changed_value_commitment(values: &mut TemplateValues) {
    values.value_commitment = Pedersen::from(transient_crypto::curve::EmbeddedFr::from(104u64));
}

#[cfg(feature = "proof-verifying")]
fn changed_public_key(values: &mut TemplateValues) {
    values.public_key = CoinPublicKey(HashOutput([105u8; 32]));
}

#[cfg(feature = "proof-verifying")]
fn changed_coin_commitment(values: &mut TemplateValues) {
    values.coin_commitment = Commitment(HashOutput([106u8; 32]));
}

#[cfg(feature = "proof-verifying")]
fn changed_coin_binding_tag(values: &mut TemplateValues) {
    values.coin_binding_tag = Fr::from(107u64);
}

#[cfg(feature = "proof-verifying")]
fn changed_commitment_sk(values: &mut TemplateValues) {
    values.commitment_sk = Fr::from(108u64);
}

#[cfg(feature = "proof-verifying")]
fn wallet_statement_from_values(values: &TemplateValues) -> Vec<Fr> {
    wallet_attestation_statement(values.public_key, values.commitment_sk)
}

#[cfg(feature = "proof-verifying")]
fn client_statement_from_values(values: &TemplateValues) -> Vec<Fr> {
    client_derivation_statement(
        values.public_key,
        values.nullifier.0.0,
        values.coin_binding_tag,
        values.commitment_sk,
    )
}

#[cfg(feature = "proof-verifying")]
fn spend_statement_from_values(values: &TemplateValues) -> Vec<Fr> {
    let input: Input<Proof, InMemoryDB> = Input {
        nullifier: values.nullifier,
        value_commitment: values.value_commitment,
        contract_address: None,
        merkle_tree_root: values.merkle_tree_root,
        proof: std::sync::Arc::new(Proof(Vec::new())),
    };
    let split = SplitPublicInputs {
        public_key: values.public_key,
        coin_commitment: values.coin_commitment,
        coin_binding_tag: values.coin_binding_tag,
        commitment_sk: values.commitment_sk,
    };
    spend_split_statement(&input, &split, values.segment)
}

#[cfg(feature = "proof-verifying")]
fn frs_to_native(values: Vec<Fr>) -> Vec<F> {
    values.into_iter().map(|value| value.0).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_envelope_round_trips() {
        let bundle = SplitWrapperProofBundle::new(Proof(vec![1, 2, 3]), vec![4, 5, 6]);
        let encoded = bundle.clone().encode();
        assert!(SplitWrapperProofBundle::is_v4(&encoded));
        assert_eq!(SplitWrapperProofBundle::decode(&encoded), Ok(bundle));
    }

    #[test]
    fn v4_envelope_rejects_malformed_bytes() {
        assert!(SplitWrapperProofBundle::decode(&Proof(b"wrong".to_vec())).is_err());

        let mut truncated = SPLIT_WRAPPER_BUNDLE_MAGIC.to_vec();
        truncated.extend_from_slice(&3u32.to_le_bytes());
        truncated.extend_from_slice(&[1, 2]);
        assert!(SplitWrapperProofBundle::decode(&Proof(truncated)).is_err());

        let mut missing_acc = SPLIT_WRAPPER_BUNDLE_MAGIC.to_vec();
        append_len_prefixed(&mut missing_acc, &[1, 2, 3]);
        assert!(SplitWrapperProofBundle::decode(&Proof(missing_acc)).is_err());

        let mut trailing = SplitWrapperProofBundle::new(Proof(vec![1]), vec![2]).encode();
        trailing.0.push(3);
        assert!(SplitWrapperProofBundle::decode(&trailing).is_err());
    }

    #[test]
    fn v4_envelope_exposes_only_wrapper_proof_and_accumulator() {
        let encoded = SplitWrapperProofBundle::new(Proof(vec![9]), vec![8]).encode();
        let decoded = match crate::structure::ZswapInputProof::decode(&encoded).unwrap() {
            crate::structure::ZswapInputProof::SplitWrapped(bundle) => bundle,
            crate::structure::ZswapInputProof::Plain(_)
            | crate::structure::ZswapInputProof::Split(_) => {
                panic!("v4 envelope decoded as non-v4 input proof")
            }
        };
        assert_eq!(decoded.wrapper_proof, Proof(vec![9]));
        assert_eq!(decoded.aggregate_accumulator, vec![8]);
    }
}
