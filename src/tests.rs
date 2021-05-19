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
use ark_crypto_primitives::{CommitmentScheme, FixedLengthCRH};
use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use x25519_dalek::{PublicKey, StaticSecret};

#[test]
fn manta_dh() {
	let seed = [1u8; 32];
	let mut rng = ChaCha20Rng::from_seed(seed);
	let receiver_sk = StaticSecret::new(rng.clone());
	let receiver_pk = PublicKey::from(&receiver_sk);
	let receiver_pk_bytes = receiver_pk.to_bytes();
	let receiver_sk_bytes = receiver_sk.to_bytes();
	let value = 12345678;
	let cipher: [u8; 48] = <MantaCrypto as Ecies>::encrypt(&receiver_pk_bytes, &value, &mut rng);
	println!("enc success");
	let rec_value = <MantaCrypto as Ecies>::decrypt(&receiver_sk_bytes, &cipher);
	assert_eq!(value, rec_value);
}

#[test]
fn test_param_serdes() {
	let hash_param_seed = [1u8; 32];
	let mut rng = ChaCha20Rng::from_seed(hash_param_seed);
	let hash_param = Hash::setup(&mut rng).unwrap();
	let mut buf: Vec<u8> = vec![];

	hash_param.serialize(&mut buf);
	let buf: &[u8] = buf.as_ref();
	let hash_param2 = HashParam::deserialize(buf);
	assert_eq!(hash_param.generators, hash_param2.generators);

	let commit_param_seed = [2u8; 32];
	let mut rng = ChaCha20Rng::from_seed(commit_param_seed);
	let commit_param = param::CommitmentScheme::setup(&mut rng).unwrap();
	let mut buf: Vec<u8> = vec![];

	commit_param.serialize(&mut buf);
	let buf: &[u8] = buf.as_ref();
	let commit_param2 = CommitmentParam::deserialize(buf);
	assert_eq!(commit_param.generators, commit_param2.generators);
	assert_eq!(
		commit_param.randomness_generator,
		commit_param2.randomness_generator
	);
}

// this is a placeholder
// todo: write more tests
// 1. serdes
// 2. regenerate parameters and check against constants.rs file
