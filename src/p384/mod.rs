// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! # Anonymous Credit Tokens — P-384 ciphersuite
//!
//! A Rust implementation of an Anonymous Credit Scheme (ACS) that enables
//! privacy-preserving payment systems for web applications and services.
//!
//! ## WARNING
//!
//! This cryptography is experimental and unaudited. Do not use in production environments
//! without thorough security review.
//!
//! ## Overview
//!
//! This module provides the P-384 (secp384r1) ciphersuite for the Anonymous Credit Token
//! protocol. P-384 provides a higher security level than P-256 (192-bit vs 128-bit).
//! See the [`p256`](crate::p256) module documentation for full protocol details.

use crate::ciphersuite::{CborError, Ciphersuite};
use ciborium::value::Value;
use elliptic_curve::hash2curve::{ExpandMsgXmd, FromOkm, GroupDigest};
use elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint, ToEncodedPoint};
use elliptic_curve::PrimeField;
use p384_crate::{AffinePoint, ProjectivePoint};
use sha2::Sha384;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

// Re-export types used in the public API.
pub use p384_crate::Scalar;
pub use rand_core::{self, CryptoRngCore};
pub use crate::ciphersuite::{ErrorCode, ErrorMsg, ParamsError};

// ── Type aliases ────────────────────────────────────────────────────────

/// The private key of the issuer, used to issue and refund credit tokens.
pub type PrivateKey = crate::protocol::PrivateKey<P384>;

/// The public key of the issuer, used to verify credit tokens.
pub type PublicKey = crate::protocol::PublicKey<P384>;

/// System parameters that define the cryptographic setup for the anonymous credentials scheme.
pub type Params = crate::protocol::Params<P384>;

/// Client state maintained during the issuance protocol.
pub type PreIssuance = crate::protocol::PreIssuance<P384>;

/// A request sent by the client to the issuer to obtain a credit token.
pub type IssuanceRequest = crate::protocol::IssuanceRequest<P384>;

/// The issuer's response to a client's issuance request.
pub type IssuanceResponse = crate::protocol::IssuanceResponse<P384>;

/// The credit token used to store and spend anonymous credits.
pub type CreditToken = crate::protocol::CreditToken<P384>;

/// A zero-knowledge proof that allows spending credits anonymously.
pub type SpendProof<const L: usize> = crate::protocol::SpendProof<P384, L>;

/// Client state maintained during the refund protocol.
pub type PreRefund = crate::protocol::PreRefund<P384>;

/// The issuer's response to a spending proof, used to create a new credit token.
pub type Refund = crate::protocol::Refund<P384>;

// ── P-384 ciphersuite marker type ──────────────────────────────────────

/// The P-384 ciphersuite marker type.
#[derive(Debug, Clone, Copy, Zeroize)]
pub struct P384;

impl Ciphersuite for P384 {
    type Point = ProjectivePoint;
    type Scalar = Scalar;
    type ParamPoint = ProjectivePoint;
    type CompressedPoint = [u8; 49]; // SEC1: 1 prefix + 48 x-coordinate
    type ScalarBytes = [u8; 48];

    const PROTOCOL_VERSION: &'static [u8] = b"p384 anonymous-credits v1.0";

    // ── Scalar operations ──────────────────────────────────────────

    fn scalar_to_u128(s: &Scalar) -> Option<u128> {
        let bytes: [u8; 48] = s.to_repr().into();
        // Big-endian: bytes[0..32] are high, bytes[32..48] are low 128 bits
        if bytes[..32].iter().any(|&b| b != 0) {
            return None;
        }
        Some(u128::from_be_bytes(bytes[32..48].try_into().unwrap()))
    }

    fn scalar_from_u128(v: u128) -> Scalar {
        let mut bytes = [0u8; 48];
        bytes[32..48].copy_from_slice(&v.to_be_bytes());
        Scalar::from_repr(bytes.into()).unwrap()
    }

    fn scalar_fits_in_bits<const L: usize>(s: &Scalar) -> bool {
        let bytes: [u8; 48] = s.to_repr().into();
        // Big-endian: bytes[0] is the MSB, bytes[47] is the LSB
        let full_bytes_used = L / 8;
        let rem_bits = L % 8;
        let boundary = 48 - full_bytes_used - usize::from(rem_bits != 0);
        let mut any_high = 0u8;
        for &b in &bytes[..boundary] {
            any_high |= b;
        }
        if rem_bits != 0 {
            any_high |= bytes[boundary] >> rem_bits;
        }
        bool::from(any_high.ct_eq(&0))
    }

    fn bits_of<const L: usize>(s: Self::Scalar) -> [Choice; L] {
        let bytes: [u8; 48] = s.to_repr().into();
        let mut result = [Choice::from(0u8); L];
        // Big-endian: byte[47] contains bits 0-7, byte[46] contains bits 8-15, etc.
        result.iter_mut().enumerate().for_each(|(i, elem)| {
            let byte_idx = 47 - (i / 8);
            *elem = Choice::from((bytes[byte_idx] >> (i % 8)) & 1);
        });
        result
    }

    fn scalar_to_bytes(s: &Scalar) -> [u8; 48] {
        s.to_repr().into()
    }

    fn scalar_invert(s: &Scalar) -> Scalar {
        s.invert().unwrap()
    }

    // ── Point operations ───────────────────────────────────────────

    fn generator_mul(s: &Scalar) -> ProjectivePoint {
        ProjectivePoint::GENERATOR * s
    }

    fn multiscalar_mul(scalars: &[Scalar], points: &[ProjectivePoint]) -> ProjectivePoint {
        scalars
            .iter()
            .zip(points.iter())
            .fold(ProjectivePoint::IDENTITY, |acc, (s, p)| acc + *p * s)
    }

    // ── ParamPoint operations (identity for P-384: ParamPoint = Point) ─

    fn to_param_point(p: &ProjectivePoint) -> ProjectivePoint {
        *p
    }

    fn param_to_point(pp: &ProjectivePoint) -> ProjectivePoint {
        *pp
    }

    fn param_mul(pp: &ProjectivePoint, s: &Scalar) -> ProjectivePoint {
        *pp * s
    }

    // ── Transcript operations ──────────────────────────────────────

    fn challenge_from_hasher(hasher: blake3::Hasher) -> Scalar {
        let mut reader = hasher.finalize_xof();
        // Extract 72 bytes for FromOkm. L = ceil((ceil(log2(q)) + k) / 8)
        // = ceil((384 + 128) / 8) = 64, but RFC 9380 specifies L=72 for P-384.
        let mut output = [0u8; 72];
        reader.fill(&mut output);
        <Scalar as FromOkm>::from_okm(output[..].into())
    }

    fn hash_to_point(domain_separator: &str, seed: &[u8], counter: u32) -> ProjectivePoint {
        let mut hasher = blake3::Hasher::new();

        // Add domain separator with length prefix
        let ds_bytes = domain_separator.as_bytes();
        hasher.update(&(ds_bytes.len() as u64).to_be_bytes());
        hasher.update(ds_bytes);

        // Add seed with length prefix
        hasher.update(&(seed.len() as u64).to_be_bytes());
        hasher.update(seed);

        // Add counter with length prefix (4 bytes for u32)
        hasher.update(&(4u64).to_be_bytes());
        hasher.update(&counter.to_le_bytes());

        // BLAKE3 hash → 32-byte msg (not XOF)
        let msg = hasher.finalize();

        // hash_to_curve using P384_XMD:SHA-384_SSWU_RO_ (RFC 9380)
        let dst = format!("ACT-P384-BLAKE3_H2C_{}", domain_separator);
        p384_crate::NistP384::hash_from_bytes::<ExpandMsgXmd<Sha384>>(
            &[msg.as_bytes()],
            &[dst.as_bytes()],
        )
        .unwrap()
    }

    fn encode_point_for_transcript(point: &ProjectivePoint) -> [u8; 49] {
        let encoded = point.to_affine().to_encoded_point(true);
        let bytes = encoded.as_bytes();
        debug_assert_eq!(bytes.len(), 49);
        let mut out = [0u8; 49];
        out.copy_from_slice(bytes);
        out
    }

    // ── CBOR operations ────────────────────────────────────────────

    fn encode_point_cbor(point: &ProjectivePoint) -> Value {
        let affine = point.to_affine();
        let encoded = affine.to_encoded_point(true);
        Value::Bytes(encoded.as_bytes().to_vec())
    }

    fn decode_point_cbor(value: &Value) -> Result<ProjectivePoint, CborError> {
        match value {
            Value::Bytes(bytes) if bytes.len() == 49 => {
                let encoded = EncodedPoint::<p384_crate::NistP384>::from_bytes(bytes)
                    .map_err(|_| CborError::InvalidValue("invalid SEC1 encoding"))?;
                let affine = AffinePoint::from_encoded_point(&encoded);
                Option::<AffinePoint>::from(affine)
                    .map(ProjectivePoint::from)
                    .ok_or(CborError::InvalidValue("invalid P-384 point"))
            }
            _ => Err(CborError::InvalidStructure(
                "expected 49-byte array for point",
            )),
        }
    }

    fn encode_scalar_cbor(scalar: &Scalar) -> Value {
        Value::Bytes(scalar.to_repr().to_vec())
    }

    fn decode_scalar_cbor(value: &Value) -> Result<Scalar, CborError> {
        match value {
            Value::Bytes(bytes) if bytes.len() == 48 => {
                let arr: [u8; 48] = bytes.as_slice().try_into().unwrap();
                let repr = p384_crate::FieldBytes::from(arr);
                let scalar = Scalar::from_repr(repr);
                Option::from(scalar)
                    .ok_or(CborError::InvalidValue("non-canonical scalar encoding"))
            }
            _ => Err(CborError::InvalidStructure(
                "expected 48-byte array for scalar",
            )),
        }
    }
}

// ── Thin wrapper functions ─────────────────────────────────────────────

/// Attempts to convert a Scalar to a u128 value.
///
/// Returns `None` if the Scalar represents a value outside the u128 range.
pub fn scalar_to_u128(scalar: &Scalar) -> Option<u128> {
    P384::scalar_to_u128(scalar)
}

/// Converts a Scalar back to a credit amount, validating that it fits within L bits.
pub fn scalar_to_credit<const L: usize>(scalar: &Scalar) -> Result<u128, ErrorCode> {
    crate::protocol::scalar_to_credit::<P384, L>(scalar)
}

/// Converts a credit amount to a Scalar, validating that it is within the valid range.
pub fn credit_to_scalar<const L: usize>(amount: u128) -> Result<Scalar, ErrorCode> {
    crate::protocol::credit_to_scalar::<P384, L>(amount)
}

#[cfg(test)]
mod tests;
