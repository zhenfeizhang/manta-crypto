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

use ark_crypto_primitives::{CryptoError, Error as StdError};
use ark_serialize::SerializationError;
use ark_std::{fmt, io::Error as IoError};
use ark_relations::r1cs::SynthesisError;

/// This is an error that could occur within manta-crypto
#[derive(Debug)]
pub enum MantaCryptoErrors {
	ChecksumFail,
	ArkSerialError(SerializationError),
	ArkCryptoError(CryptoError),
	ArkStdError(StdError),
	ArkIoError(IoError),
	ArkSynthesisError(SynthesisError),
}

impl ark_std::error::Error for MantaCryptoErrors {}

impl From<SerializationError> for MantaCryptoErrors {
	fn from(e: SerializationError) -> MantaCryptoErrors {
		MantaCryptoErrors::ArkSerialError(e)
	}
}

impl From<CryptoError> for MantaCryptoErrors {
	fn from(e: CryptoError) -> MantaCryptoErrors {
		MantaCryptoErrors::ArkCryptoError(e)
	}
}

impl From<StdError> for MantaCryptoErrors {
	fn from(e: StdError) -> MantaCryptoErrors {
		MantaCryptoErrors::ArkStdError(e)
	}
}

impl From<IoError> for MantaCryptoErrors {
	fn from(e: IoError) -> MantaCryptoErrors {
		MantaCryptoErrors::ArkIoError(e)
	}
}

impl fmt::Display for MantaCryptoErrors {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
		match self {
			Self::ChecksumFail => write!(f, "Checksum failed"),
			Self::ArkSerialError(err) => write!(f, "Ark serial error {:?}", err),
			Self::ArkIoError(err) => write!(f, "I/O error: {:?}", err),
			Self::ArkCryptoError(err) => write!(f, "Ark crypto error: {:?}", err),
			Self::ArkStdError(err) => write!(f, "Ark std error: {:?}", err),
			Self::ArkSynthesisError(err) => write!(f, "Ark synthesis error: {:?}", err),
		}
	}
}
