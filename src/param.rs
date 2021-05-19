// Copyright 2019-2021 Manta Network.
// This file is part of manta-crypto.
//
// manta-crypto is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// manta-crypto is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with manta-crypto.  If not, see <http://www.gnu.org/licenses/>.

use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::{
	commitment::pedersen::{constraints::CommGadget, Commitment, Window},
	crh::{
		pedersen::{constraints::CRHGadget, CRH},
		FixedLengthCRH, FixedLengthCRHGadget,
	},
	merkle_tree::{Config, Digest, Path},
	CommitmentScheme as ArkCommitmentScheme, MerkleTree, SNARK, *,
};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsParameters, EdwardsProjective, Fq};
use ark_groth16::Groth16;
use ark_r1cs_std::{fields::fp::FpVar, groups::curves::twisted_edwards::AffineVar};

/// The seed that is used to generate ZKP parameters
pub const ZK_PPARAM_SEED: [u8; 32] = [3u8; 32];
/// The seed that is used to generate hash parameters
pub const HASH_PARAM_SEED: [u8; 32] = [1u8; 32];
/// The seed that is used to generate commitment parameters
pub const COMMIT_PARAM_SEED: [u8; 32] = [2u8; 32];

//=======================
// pedersen hash and related definitions
// the hash function is defined over the JubJub curve
//=======================
pub(crate) const PERDERSON_WINDOW_SIZE: usize = 4;
pub(crate) const PERDERSON_WINDOW_NUM: usize = 256;

/// The depth of the merkle tree.
const TREE_DEPTH: usize = 21;

#[derive(Clone)]
pub struct PedersenWindow;
impl Window for PedersenWindow {
	const WINDOW_SIZE: usize = PERDERSON_WINDOW_SIZE;
	const NUM_WINDOWS: usize = PERDERSON_WINDOW_NUM;
}
pub type Hash = CRH<EdwardsProjective, PedersenWindow>;
#[allow(dead_code)]
pub type HashOutput = <Hash as FixedLengthCRH>::Output;
pub type HashParam = <Hash as FixedLengthCRH>::Parameters;

//=======================
// Merkle tree for the ledger, using Perdersen hash
//=======================
/// Manta's parameters for the Merkle tree.
#[derive(Debug, Clone, Copy)]
pub struct MerkleTreeParams;
impl Config for MerkleTreeParams {
	const HEIGHT: usize = TREE_DEPTH;
	type H = Hash;
}

/// A merkle tree that is instantiated with Manta parameters.
pub type LedgerMerkleTree = MerkleTree<MerkleTreeParams>;
/// The root of the tree.
pub type LedgerMerkleTreeRoot = Digest<MerkleTreeParams>;

/// The membership is a path on the merkle tree, including the leaf itself.
/// It can be used to verify that a leaf is indeed on a tree.
#[allow(dead_code)]
pub type AccountMembership = Path<MerkleTreeParams>;

//=======================
// Commitments
//=======================

/// Perdersen commitment, instantiated with `ed_on_bls_12_381` curve and a `window` parameter.
pub type CommitmentScheme = Commitment<EdwardsProjective, PedersenWindow>;
/// The `window` parameter for the Perdersen commitment scheme.
pub type CommitmentParam = <CommitmentScheme as ArkCommitmentScheme>::Parameters;
#[allow(dead_code)]
pub type CommitmentOpen = <CommitmentScheme as ArkCommitmentScheme>::Randomness;
pub type CommitmentOutput = <CommitmentScheme as ArkCommitmentScheme>::Output;

// gadgets for hash function
pub type HashVar = CRHGadget<EdwardsProjective, EdwardsVar, PedersenWindow>;
pub type HashOutputVar = <HashVar as FixedLengthCRHGadget<Hash, Fq>>::OutputVar;
pub type HashParamVar = <HashVar as FixedLengthCRHGadget<Hash, Fq>>::ParametersVar;

// gadget for private coin account membership
#[allow(dead_code)]
pub type AccountMembershipVar = PathVar<MerkleTreeParams, HashVar, Fq>;

//=======================
// ZK proofs over BLS curve
//=======================
/// Proving key for the ZKP system.
pub type Groth16Pk = <Groth16<Bls12_381> as SNARK<Fq>>::ProvingKey;
/// Processed verification key for the ZKP system
pub type Groth16Pvk = <Groth16<Bls12_381> as SNARK<Fq>>::ProcessedVerifyingKey;
/// Verification key for the ZKP system
pub type Groth16Vk = <Groth16<Bls12_381> as SNARK<Fq>>::VerifyingKey;
/// Proofs for the ZKP system
pub type Groth16Proof = <Groth16<Bls12_381> as SNARK<Fq>>::Proof;

//=======================
// Commitments
//=======================
pub type CommitmentSchemeVar = CommGadget<EdwardsProjective, EdwardsVar, PedersenWindow>;
pub type CommitmentParamVar =
	<CommitmentSchemeVar as CommitmentGadget<CommitmentScheme, Fq>>::ParametersVar;
pub type MantaCoinCommitmentOpenVar =
	<CommitmentSchemeVar as CommitmentGadget<CommitmentScheme, Fq>>::RandomnessVar;
pub type MantaCoinCommitmentOutputVar = AffineVar<EdwardsParameters, FpVar<Fq>>;

//=======================
// wrapper of Blobs
//=======================
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VerificationKey {
	pub data: &'static [u8],
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Parameter {
	pub data: &'static [u8],
}
