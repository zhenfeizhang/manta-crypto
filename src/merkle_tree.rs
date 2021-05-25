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
use ark_serialize::CanonicalSerialize;
use manta_error::MantaError;

pub trait MerkleTree {
	type Param;
	type Leaf;
	type Root;
	type Tree;

	/// build a merkle tree from the leaves
	fn build_tree(
		hash_param: Self::Param,
		leaves: &[Self::Leaf],
	) -> Result<Self::Tree, MantaError>;

	/// get the root of the merkle tree
	fn root(hash_param: Self::Param, payload: &[Self::Leaf]) -> Result<Self::Root, MantaError>;
}

impl MerkleTree for MantaCrypto {
	type Param = HashParam;
	type Leaf = [u8; 32];
	type Root = [u8; 32];
	type Tree = LedgerMerkleTree;

	/// build a merkle tree from the leaves
	fn build_tree(
		hash_param: Self::Param,
		leaves: &[Self::Leaf],
	) -> Result<Self::Tree, MantaError> {
		let tree = LedgerMerkleTree::new(hash_param, leaves)?;
		Ok(tree)
	}

	/// Give a slice of the `payload`, and a hash function defined by the `hash_param`,
	/// build a merkle tree, and output the root of the tree.
	fn root(hash_param: Self::Param, leaves: &[Self::Leaf]) -> Result<Self::Root, MantaError> {
		let tree = Self::build_tree(hash_param, leaves)?;
		let root = tree.root();

		let mut bytes = [0u8; 32];
		root.serialize(bytes.as_mut())?;
		Ok(bytes)
	}
}
