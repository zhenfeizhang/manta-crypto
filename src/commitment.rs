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

use crate::*;
use ark_crypto_primitives::{
	commitment::pedersen::Randomness, CommitmentScheme as ArkCommitmentScheme,
};
use ark_ed_on_bls12_381::Fr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use manta_errors::MantaErrors;

pub trait Commitment {
	type Param;
	type Input;
	type Randomness;
	type Commitment;

	/// generate a commitment for some given input
	fn commit(
		param: &Self::Param,
		input: &Self::Input,
		randomness: &Self::Randomness,
	) -> Result<Self::Commitment, MantaErrors>;

	/// check the commitment is correct for some given input
	fn check_commitment(
		param: &Self::Param,
		input: &Self::Input,
		randomness: &Self::Randomness,
		commitment: &Self::Commitment,
	) -> Result<bool, MantaErrors>;
}

impl Commitment for MantaCrypto {
	type Param = CommitmentParam;
	type Input = Vec<u8>;
	type Randomness = [u8; 32];
	type Commitment = [u8; 32];

	fn commit(
		param: &Self::Param,
		input: &Self::Input,
		randomness: &Self::Randomness,
	) -> Result<Self::Commitment, MantaErrors> {
		let open = Randomness(Fr::deserialize(randomness.as_ref())?);
		let commit = CommitmentScheme::commit(param, input, &open)?;
		let mut commit_bytes = [0u8; 32];
		commit.serialize(commit_bytes.as_mut())?;
		Ok(commit_bytes)
	}

	fn check_commitment(
		param: &Self::Param,
		input: &Self::Input,
		randomness: &Self::Randomness,
		commitment: &Self::Commitment,
	) -> Result<bool, MantaErrors> {
		Ok(Self::commit(param, input, &randomness)? == *commitment)
	}
}
