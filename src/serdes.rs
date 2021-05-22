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

use crate::{param::*, MantaCryptoErrors};
use ark_crypto_primitives::{commitment, crh};
use ark_ed_on_bls12_381::EdwardsProjective;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
	io::{Read, Write},
	vec::Vec,
};

/// Manta's native (de)serialization trait.
pub trait MantaSerDes: Sized {
	/// Serialize a struct into a writable blob.
	fn serialize<W: Write>(&self, writer: W) -> Result<(), MantaCryptoErrors>;
	/// Deserialize a readable data into a struct.
	fn deserialize<R: Read>(reader: R) -> Result<Self, MantaCryptoErrors>;
}

impl MantaSerDes for crh::pedersen::Parameters<EdwardsProjective> {
	/// serialize the hash parameters without compression
	fn serialize<W: Write>(&self, mut writer: W) -> Result<(), MantaCryptoErrors> {
		for generators in self.generators.iter() {
			for gen in generators {
				gen.serialize_uncompressed(&mut writer)?;
			}
		}
		Ok(())
	}

	/// This function deserialize the hash parameters.
	/// warning: for efficiency reasons, we do not check the validity of deserialized elements
	/// the caller should check the CheckSum of the parameters to make sure
	/// they are consistent with the version used by the ledger.
	fn deserialize<R: Read>(mut reader: R) -> Result<Self, MantaCryptoErrors> {
		let window = PERDERSON_WINDOW_SIZE;
		let len = PERDERSON_WINDOW_NUM;

		let mut generators = Vec::new();
		for _ in 0..len {
			let mut gen = Vec::new();
			for _ in 0..window {
				gen.push(EdwardsProjective::deserialize_unchecked(&mut reader)?)
			}
			generators.push(gen);
		}

		Ok(Self { generators })
	}
}

impl MantaSerDes for commitment::pedersen::Parameters<EdwardsProjective> {
	/// Serialize the commitment parameters without data compression.
	fn serialize<W: Write>(&self, mut writer: W) -> Result<(), MantaCryptoErrors> {
		for generators in self.generators.iter() {
			for gen in generators {
				gen.serialize_uncompressed(&mut writer)?
			}
		}
		for rgen in self.randomness_generator.iter() {
			rgen.serialize_uncompressed(&mut writer)?
		}
		Ok(())
	}

	/// This function deserialize the hash parameters.
	/// __Warning__: for efficiency reasons, we do not check the validity of deserialized elements.
	/// The caller should check the CheckSum of the parameters to make sure
	/// they are consistent with the version used by the ledger.
	fn deserialize<R: Read>(mut reader: R) -> Result<Self, MantaCryptoErrors> {
		let window = PERDERSON_WINDOW_SIZE;
		let len = PERDERSON_WINDOW_NUM;

		let mut generators = Vec::new();
		for _ in 0..len {
			let mut gen = Vec::new();
			for _ in 0..window {
				gen.push(EdwardsProjective::deserialize_unchecked(&mut reader)?)
			}
			generators.push(gen);
		}
		let mut randomness_generator = Vec::new();
		for _ in 0..252 {
			randomness_generator.push(EdwardsProjective::deserialize_unchecked(&mut reader)?)
		}

		Ok(Self {
			randomness_generator,
			generators,
		})
	}
}
