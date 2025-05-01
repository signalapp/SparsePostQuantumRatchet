// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

use crate::encoding;

#[derive(Debug, thiserror::Error, Copy, Clone, PartialEq)]
pub enum Error {
    #[error("General deserialization error")]
    Deserialization,
    #[error("Error with encoder/decoder serialization")]
    EncodingDecoding,
}

impl From<encoding::polynomial::PolynomialError> for Error {
    fn from(_e: encoding::polynomial::PolynomialError) -> Error {
        Error::EncodingDecoding
    }
}
