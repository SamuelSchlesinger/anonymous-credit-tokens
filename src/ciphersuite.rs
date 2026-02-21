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

//! Ciphersuite trait and shared error types for the Anonymous Credit Token protocol.

use ciborium::value::Value;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

/// Trait abstracting over the cryptographic ciphersuite (P-256 vs Ristretto255).
///
/// Captures every divergence point between ciphersuites so that protocol logic,
/// transcript handling, and CBOR serialization can be written once as generic code.
pub trait Ciphersuite: Sized + Clone + Copy + std::fmt::Debug + Zeroize + 'static {
    /// The group element type (ProjectivePoint / RistrettoPoint).
    type Point: group::Group<Scalar = Self::Scalar>
        + ConditionallySelectable
        + ConstantTimeEq
        + Zeroize;

    /// The scalar field element type.
    type Scalar: group::ff::PrimeField + Zeroize;

    /// The type used for precomputed parameter points.
    /// `ProjectivePoint` for P-256, `RistrettoBasepointTable` for Ristretto255.
    type ParamPoint: Clone;

    /// Fixed-size compressed point encoding for transcript hashing.
    /// `[u8; 33]` for P-256 (SEC1 compressed), `[u8; 32]` for Ristretto255.
    type CompressedPoint: AsRef<[u8]> + Clone;

    /// Fixed-size scalar byte encoding for transcript hashing.
    /// `[u8; 32]` for 256-bit curves, `[u8; 48]` for P-384, `[u8; 66]` for P-521.
    type ScalarBytes: AsRef<[u8]> + Clone;

    /// Protocol version string included in every transcript.
    const PROTOCOL_VERSION: &'static [u8];

    // ── Scalar operations ──────────────────────────────────────────────

    /// Convert a scalar to u128, returning None if it doesn't fit.
    fn scalar_to_u128(s: &Self::Scalar) -> Option<u128>;

    /// Construct a scalar from a u128 value.
    fn scalar_from_u128(v: u128) -> Self::Scalar;

    /// Constant-time check: are all bits at positions >= L zero?
    fn scalar_fits_in_bits<const L: usize>(s: &Self::Scalar) -> bool;

    /// Decompose a scalar into L binary Choice values.
    fn bits_of<const L: usize>(s: Self::Scalar) -> [Choice; L];

    /// Serialize a scalar to bytes (for transcript hashing).
    fn scalar_to_bytes(s: &Self::Scalar) -> Self::ScalarBytes;

    /// Invert a scalar (assumes non-zero with negligible probability).
    fn scalar_invert(s: &Self::Scalar) -> Self::Scalar;

    // ── Point operations ───────────────────────────────────────────────

    /// Multiply the fixed generator by a scalar (uses precomputed tables when available).
    fn generator_mul(s: &Self::Scalar) -> Self::Point;

    /// Variable-time multi-scalar multiplication: sum of s_i * P_i.
    fn multiscalar_mul(scalars: &[Self::Scalar], points: &[Self::Point]) -> Self::Point;

    // ── ParamPoint operations ──────────────────────────────────────────

    /// Convert a Point to a ParamPoint (identity for P-256, create table for Ristretto).
    fn to_param_point(p: &Self::Point) -> Self::ParamPoint;

    /// Convert a ParamPoint back to a Point.
    fn param_to_point(pp: &Self::ParamPoint) -> Self::Point;

    /// Multiply a ParamPoint by a scalar.
    fn param_mul(pp: &Self::ParamPoint, s: &Self::Scalar) -> Self::Point;

    // ── Transcript operations ──────────────────────────────────────────

    /// Derive a challenge scalar from a finalized BLAKE3 hasher.
    fn challenge_from_hasher(hasher: blake3::Hasher) -> Self::Scalar;

    /// Deterministic hash-to-curve from domain separator, seed, and counter.
    fn hash_to_point(domain_separator: &str, seed: &[u8], counter: u32) -> Self::Point;

    /// Encode a point to bytes for transcript hashing.
    fn encode_point_for_transcript(point: &Self::Point) -> Self::CompressedPoint;

    // ── CBOR operations ────────────────────────────────────────────────

    /// Encode a point as a CBOR byte string value.
    fn encode_point_cbor(point: &Self::Point) -> Value;

    /// Decode a point from a CBOR byte string value.
    fn decode_point_cbor(value: &Value) -> Result<Self::Point, CborError>;

    /// Encode a scalar as a CBOR byte string value.
    fn encode_scalar_cbor(scalar: &Self::Scalar) -> Value;

    /// Decode a scalar from a CBOR byte string value (canonical check).
    fn decode_scalar_cbor(value: &Value) -> Result<Self::Scalar, CborError>;
}

// ── Shared error types ─────────────────────────────────────────────────

/// Error returned when constructing `Params` with invalid inputs.
#[derive(Debug, Clone)]
pub enum ParamsError {
    /// A domain separator component contains the reserved `:` character.
    InvalidDomainSeparator(&'static str),
}

impl std::fmt::Display for ParamsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParamsError::InvalidDomainSeparator(msg) => write!(f, "invalid domain separator: {msg}"),
        }
    }
}

impl std::error::Error for ParamsError {}

/// Error codes for the protocol as defined in Section 5.3 of the spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    /// Proof verification failed
    InvalidProof = 1,
    /// Double-spend attempt detected
    NullifierReuse = 2,
    /// Request format is invalid
    MalformedRequest = 3,
    /// Credit amount exceeds maximum (2^L - 1)
    InvalidAmount = 4,
}

impl ErrorCode {
    /// Convert from a u32 value.
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(ErrorCode::InvalidProof),
            2 => Some(ErrorCode::NullifierReuse),
            3 => Some(ErrorCode::MalformedRequest),
            4 => Some(ErrorCode::InvalidAmount),
            _ => None,
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorCode::InvalidProof => write!(f, "proof verification failed"),
            ErrorCode::NullifierReuse => write!(f, "double-spend attempt detected"),
            ErrorCode::MalformedRequest => write!(f, "request format is invalid"),
            ErrorCode::InvalidAmount => write!(f, "credit amount exceeds maximum"),
        }
    }
}

impl std::error::Error for ErrorCode {}

/// An error message as defined in Section 4.2 of the spec.
///
/// ```text
/// ErrorMsg = {
///     1: uint,   ; error_code
///     2: tstr    ; error_message (for debugging only)
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ErrorMsg {
    /// The error code identifying the type of error.
    pub error_code: ErrorCode,
    /// A human-readable error message for debugging.
    pub error_message: String,
}

impl std::fmt::Display for ErrorMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.error_code, self.error_message)
    }
}

impl std::error::Error for ErrorMsg {}

/// Error type for CBOR serialization/deserialization.
#[derive(Debug)]
pub enum CborError {
    /// Error from ciborium library
    Ciborium(ciborium::de::Error<std::io::Error>),
    /// Invalid CBOR structure
    InvalidStructure(&'static str),
    /// Invalid field value
    InvalidValue(&'static str),
    /// Input exceeds maximum size
    InputTooLarge,
}

impl std::fmt::Display for CborError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CborError::Ciborium(e) => write!(f, "CBOR error: {e}"),
            CborError::InvalidStructure(msg) => write!(f, "invalid CBOR structure: {msg}"),
            CborError::InvalidValue(msg) => write!(f, "invalid CBOR value: {msg}"),
            CborError::InputTooLarge => write!(f, "CBOR input exceeds maximum size"),
        }
    }
}

impl std::error::Error for CborError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CborError::Ciborium(e) => Some(e),
            CborError::InvalidStructure(_) | CborError::InvalidValue(_) | CborError::InputTooLarge => None,
        }
    }
}

impl From<ciborium::de::Error<std::io::Error>> for CborError {
    fn from(e: ciborium::de::Error<std::io::Error>) -> Self {
        CborError::Ciborium(e)
    }
}

impl From<ciborium::ser::Error<std::io::Error>> for CborError {
    fn from(_: ciborium::ser::Error<std::io::Error>) -> Self {
        CborError::InvalidStructure("serialization error")
    }
}
