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

//! # Anonymous Credit Tokens — P-521 ciphersuite
//!
//! A Rust implementation of an Anonymous Credit Scheme (ACS) that enables
//! privacy-preserving payment systems for web applications and services.
//!
//! ## WARNING
//!
//! This cryptography is experimental and unaudited. Do not use in production environments
//! without thorough security review. The `p521` crate's arithmetic has never been
//! independently audited and its constant-time properties are not thoroughly assessed.
//!
//! ## Overview
//!
//! This module provides the P-521 (secp521r1) ciphersuite for the Anonymous Credit Token
//! protocol. P-521 provides a higher security level than P-384 (256-bit vs 192-bit).
//! See the [`p256`](crate::p256) module documentation for full protocol details.
//!
//! ## Notes
//!
//! Unlike P-256 and P-384, the `p521` crate does not provide a `hash2curve` feature.
//! `hash_to_point` uses a try-and-increment approach instead. This is acceptable because
//! `hash_to_point` is only called for deterministic, public parameter generation.

use crate::ciphersuite::{CborError, Ciphersuite};
use ciborium::value::Value;
use elliptic_curve::PrimeField;
use elliptic_curve::ops::Reduce;
use elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint, ToEncodedPoint};
use p521_crate::{AffinePoint, ProjectivePoint, U576};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

// Re-export types used in the public API.
pub use p521_crate::Scalar;
pub use rand_core::{self, CryptoRngCore};
pub use crate::ciphersuite::{ErrorCode, ErrorMsg, ParamsError};

// ── Type aliases ────────────────────────────────────────────────────────

/// The private key of the issuer, used to issue and refund credit tokens.
pub type PrivateKey = crate::protocol::PrivateKey<P521>;

/// The public key of the issuer, used to verify credit tokens.
pub type PublicKey = crate::protocol::PublicKey<P521>;

/// System parameters that define the cryptographic setup for the anonymous credentials scheme.
pub type Params = crate::protocol::Params<P521>;

/// Client state maintained during the issuance protocol.
pub type PreIssuance = crate::protocol::PreIssuance<P521>;

/// A request sent by the client to the issuer to obtain a credit token.
pub type IssuanceRequest = crate::protocol::IssuanceRequest<P521>;

/// The issuer's response to a client's issuance request.
pub type IssuanceResponse = crate::protocol::IssuanceResponse<P521>;

/// The credit token used to store and spend anonymous credits.
pub type CreditToken = crate::protocol::CreditToken<P521>;

/// A zero-knowledge proof that allows spending credits anonymously.
pub type SpendProof<const L: usize> = crate::protocol::SpendProof<P521, L>;

/// Client state maintained during the refund protocol.
pub type PreRefund = crate::protocol::PreRefund<P521>;

/// The issuer's response to a spending proof, used to create a new credit token.
pub type Refund = crate::protocol::Refund<P521>;

// ── P-521 ciphersuite marker type ──────────────────────────────────────

/// The P-521 ciphersuite marker type.
#[derive(Debug, Clone, Copy, Zeroize)]
pub struct P521;

impl Ciphersuite for P521 {
    type Point = ProjectivePoint;
    type Scalar = Scalar;
    type ParamPoint = ProjectivePoint;
    type CompressedPoint = [u8; 67]; // SEC1: 1 prefix + 66 x-coordinate
    type ScalarBytes = [u8; 66];

    const PROTOCOL_VERSION: &'static [u8] = b"p521 anonymous-credits v1.0";

    // ── Scalar operations ──────────────────────────────────────────

    fn scalar_to_u128(s: &Scalar) -> Option<u128> {
        let repr = s.to_repr();
        let bytes: &[u8] = repr.as_ref();
        // Big-endian: bytes[0..50] are high, bytes[50..66] are low 128 bits
        if bytes[..50].iter().any(|&b| b != 0) {
            return None;
        }
        Some(u128::from_be_bytes(bytes[50..66].try_into().unwrap()))
    }

    fn scalar_from_u128(v: u128) -> Scalar {
        let mut bytes = [0u8; 66];
        bytes[50..66].copy_from_slice(&v.to_be_bytes());
        let mut repr = p521_crate::FieldBytes::default();
        repr.copy_from_slice(&bytes);
        Scalar::from_repr(repr).unwrap()
    }

    fn scalar_fits_in_bits<const L: usize>(s: &Scalar) -> bool {
        let repr = s.to_repr();
        let bytes: &[u8] = repr.as_ref();
        // Big-endian: bytes[0] is the MSB, bytes[65] is the LSB
        let full_bytes_used = L / 8;
        let rem_bits = L % 8;
        let boundary = 66 - full_bytes_used - usize::from(rem_bits != 0);
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
        let repr = s.to_repr();
        let bytes: &[u8] = repr.as_ref();
        let mut result = [Choice::from(0u8); L];
        // Big-endian: byte[65] contains bits 0-7, byte[64] contains bits 8-15, etc.
        result.iter_mut().enumerate().for_each(|(i, elem)| {
            let byte_idx = 65 - (i / 8);
            *elem = Choice::from((bytes[byte_idx] >> (i % 8)) & 1);
        });
        result
    }

    fn scalar_to_bytes(s: &Scalar) -> [u8; 66] {
        let repr = s.to_repr();
        let mut out = [0u8; 66];
        out.copy_from_slice(repr.as_ref());
        out
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

    // ── ParamPoint operations (identity for P-521: ParamPoint = Point) ─

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
        // Extract 72 bytes (576 bits) for Reduce<U576>. The P-521 order n uses
        // ~521 bits, so 576 - 521 = 55 extra bits of entropy ensures negligible
        // bias for the Fiat-Shamir transform.
        let mut output = [0u8; 72];
        reader.fill(&mut output);
        <Scalar as Reduce<U576>>::reduce(U576::from_be_slice(&output))
    }

    fn hash_to_point(domain_separator: &str, seed: &[u8], counter: u32) -> ProjectivePoint {
        // The p521 crate does not provide hash2curve. Use a try-and-increment
        // approach: hash the inputs to a candidate x-coordinate, try to
        // decompress, and increment on failure. This is only used for
        // deterministic public parameter generation so timing leaks are acceptable.
        let mut hasher = blake3::Hasher::new();

        let ds_bytes = domain_separator.as_bytes();
        hasher.update(&(ds_bytes.len() as u64).to_be_bytes());
        hasher.update(ds_bytes);

        hasher.update(&(seed.len() as u64).to_be_bytes());
        hasher.update(seed);

        hasher.update(&(4u64).to_be_bytes());
        hasher.update(&counter.to_le_bytes());

        let base_hash = hasher.finalize();

        for attempt in 0u32.. {
            let mut attempt_hasher = blake3::Hasher::new();
            attempt_hasher.update(b"ACT-P521-H2C-TAI");
            attempt_hasher.update(base_hash.as_bytes());
            attempt_hasher.update(&attempt.to_le_bytes());

            let mut xof = attempt_hasher.finalize_xof();
            let mut x_bytes = [0u8; 66];
            xof.fill(&mut x_bytes);

            // P-521 uses 521 bits = 65 bytes + 1 bit. Clear the unused top 7 bits
            // of the first byte so x < 2^521.
            x_bytes[0] &= 0x01;

            // Try SEC1 compressed point decompression (0x02 prefix = even y)
            let mut compressed = [0u8; 67];
            compressed[0] = 0x02;
            compressed[1..].copy_from_slice(&x_bytes);

            if let Ok(encoded) = EncodedPoint::<p521_crate::NistP521>::from_bytes(&compressed[..]) {
                let affine = AffinePoint::from_encoded_point(&encoded);
                if let Some(point) = Option::<AffinePoint>::from(affine) {
                    let proj = ProjectivePoint::from(point);
                    // Reject identity
                    if !bool::from(proj.ct_eq(&ProjectivePoint::IDENTITY)) {
                        return proj;
                    }
                }
            }
        }
        unreachable!("hash_to_point must find a valid point")
    }

    fn encode_point_for_transcript(point: &ProjectivePoint) -> [u8; 67] {
        let encoded = point.to_affine().to_encoded_point(true);
        let bytes = encoded.as_bytes();
        debug_assert_eq!(bytes.len(), 67);
        let mut out = [0u8; 67];
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
            Value::Bytes(bytes) if bytes.len() == 67 => {
                let encoded = EncodedPoint::<p521_crate::NistP521>::from_bytes(bytes)
                    .map_err(|_| CborError::InvalidValue("invalid SEC1 encoding"))?;
                let affine = AffinePoint::from_encoded_point(&encoded);
                Option::<AffinePoint>::from(affine)
                    .map(ProjectivePoint::from)
                    .ok_or(CborError::InvalidValue("invalid P-521 point"))
            }
            _ => Err(CborError::InvalidStructure(
                "expected 67-byte array for point",
            )),
        }
    }

    fn encode_scalar_cbor(scalar: &Scalar) -> Value {
        Value::Bytes(scalar.to_repr().to_vec())
    }

    fn decode_scalar_cbor(value: &Value) -> Result<Scalar, CborError> {
        match value {
            Value::Bytes(bytes) if bytes.len() == 66 => {
                let arr: [u8; 66] = bytes.as_slice().try_into().unwrap();
                let mut repr = p521_crate::FieldBytes::default();
                repr.copy_from_slice(&arr);
                let scalar = Scalar::from_repr(repr);
                Option::from(scalar)
                    .ok_or(CborError::InvalidValue("non-canonical scalar encoding"))
            }
            _ => Err(CborError::InvalidStructure(
                "expected 66-byte array for scalar",
            )),
        }
    }
}

// ── Thin wrapper functions ─────────────────────────────────────────────

/// Attempts to convert a Scalar to a u128 value.
///
/// Returns `None` if the Scalar represents a value outside the u128 range.
pub fn scalar_to_u128(scalar: &Scalar) -> Option<u128> {
    P521::scalar_to_u128(scalar)
}

/// Converts a Scalar back to a credit amount, validating that it fits within L bits.
pub fn scalar_to_credit<const L: usize>(scalar: &Scalar) -> Result<u128, ErrorCode> {
    crate::protocol::scalar_to_credit::<P521, L>(scalar)
}

/// Converts a credit amount to a Scalar, validating that it is within the valid range.
pub fn credit_to_scalar<const L: usize>(amount: u128) -> Result<Scalar, ErrorCode> {
    crate::protocol::credit_to_scalar::<P521, L>(amount)
}

#[cfg(test)]
mod tests;
