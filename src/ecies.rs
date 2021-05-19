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

//
// You should have received a copy of the GNU General Public License
// along with pallet-manta-pay.  If not, see <http://www.gnu.org/licenses/>.

//! This file implements Diffie-Hellman Key Agreement for value encryption
//! TODO: maybe we should simply use ecies crate
//! <https://github.com/phayes/ecies-ed25519/>
use crate::MantaCrypto;
use aes::{cipher::NewBlockCipher, Aes256, BlockDecrypt, BlockEncrypt};
use ark_std::rand::{CryptoRng, RngCore};
use blake2::{Blake2s, Digest};
use generic_array::GenericArray;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

pub trait Ecies {
	type PublicKey;
	type PrivateKey;
	type Message;
	type Ciphertext;

	/// Genrate a pair of keys
	fn keygen<R: RngCore + CryptoRng>(rng: &mut R) -> (Self::PublicKey, Self::PrivateKey);

	/// Encrypt the message under the input public key.
	fn encrypt<R: RngCore + CryptoRng>(
		pk: &Self::PublicKey,
		message: &Self::Message,
		rng: &mut R,
	) -> Self::Ciphertext;

	/// Decrypt a ciphertext with a secret key.
	fn decrypt(sk: &Self::PrivateKey, cipher: &Self::Ciphertext) -> Self::Message;
}

impl Ecies for MantaCrypto {
	type PublicKey = [u8; 32];
	type PrivateKey = [u8; 32];
	type Message = u64;
	type Ciphertext = [u8; 48];

	/// Generate a pair of keys
	fn keygen<R: RngCore + CryptoRng>(rng: &mut R) -> (Self::PublicKey, Self::PrivateKey) {
		let sk = StaticSecret::new(rng);
		let pk = PublicKey::from(&sk);
		(pk.to_bytes(), sk.to_bytes())
	}

	/// Encrypt the message under the input public key.
	///
	/// # <weight>
	/// Steps:
	///     1. sample a random, ephemeral field element: ephemeral_sk
	///     2. compute the group element ephemeral_pk
	///     3. compute the shared secret ss = pk^ephemeral_sk
	///     4. set aes_key = KDF("manta kdf instantiated with blake2s hash function" | ss)
	///     5. compute c = aes_enc(message.to_le_bytes(), aes_key)
	///     6. return [c | pk]
	/// # </weight>
	fn encrypt<R: RngCore + CryptoRng>(
		pk: &Self::PublicKey,
		message: &Self::Message,
		rng: &mut R,
	) -> Self::Ciphertext {
		let ephemeral_sk = EphemeralSecret::new(rng);
		let ephemeral_pk = PublicKey::from(&ephemeral_sk);

		let pk = PublicKey::from(*pk);
		let shared_secret = ephemeral_sk.diffie_hellman(&pk);
		let ss = manta_kdf(&shared_secret.to_bytes());
		let aes_key = GenericArray::from_slice(&ss);

		let msg = [message.to_le_bytes().as_ref(), [0u8; 8].as_ref()].concat();
		assert_eq!(msg.len(), 16);
		let mut block = GenericArray::clone_from_slice(&msg);
		let cipher = Aes256::new(&aes_key);
		cipher.encrypt_block(&mut block);

		let mut res = [0u8; 48];
		res[0..16].copy_from_slice(block.as_slice());
		res[16..48].copy_from_slice(ephemeral_pk.to_bytes().as_ref());
		res
	}

	/// Decrypt a ciphertext with a secret key.
	///
	/// # <weight>
	/// Steps:
	///     1. parse cipher as [c | pk]
	///     2. compute the shared secret ss = pk^sk
	///     3. set aes_key = KDF("manta kdf instantiated with blake2s hash function" | ss)
	///     4. compute m = aes_dec(cipher, aes_key)
	///     5. return m as u64
	/// # </weight>
	fn decrypt(sk: &Self::PrivateKey, cipher: &Self::Ciphertext) -> Self::Message {
		let sk = StaticSecret::from(*sk);

		let mut pk_bytes = [0u8; 32];
		pk_bytes.copy_from_slice(cipher[16..48].as_ref());
		let pk = PublicKey::from(pk_bytes);

		let shared_secret = sk.diffie_hellman(&pk);
		let ss = manta_kdf(&shared_secret.to_bytes());
		let aes_key = GenericArray::from_slice(&ss);
		let mut block = [0u8; 16];
		block.copy_from_slice(cipher[0..16].as_ref());
		let mut block = GenericArray::from_mut_slice(&mut block);
		let cipher = Aes256::new(&aes_key);
		cipher.decrypt_block(&mut block);

		(block[0] as u64)
			+ ((block[1] as u64) << 8)
			+ ((block[2] as u64) << 16)
			+ ((block[3] as u64) << 24)
			+ ((block[4] as u64) << 32)
			+ ((block[5] as u64) << 40)
			+ ((block[6] as u64) << 48)
			+ ((block[7] as u64) << 56)
	}
}

// this function is a wrapper of blake2s: m = hkdf-extract(salt, seed)
// with a fixed salt
fn manta_kdf(input: &[u8]) -> [u8; 32] {
	let salt = "manta kdf instantiated with blake2s hash function";
	let mut hasher = Blake2s::new();
	hasher.update([input, salt.as_bytes()].concat());
	let digest = hasher.finalize();
	let mut res = [0u8; 32];
	res.copy_from_slice(digest.as_slice());
	res
}
