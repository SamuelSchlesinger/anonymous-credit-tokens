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

//! # Anonymous Credit Tokens — Ristretto255 ciphersuite
//!
//! A Rust implementation of an Anonymous Credit Scheme (ACS) that enables
//! privacy-preserving payment systems for web applications and services.
//!
//! ## WARNING
//!
//! This cryptography is experimental and unaudited. Do not use in production environments
//! without thorough security review.
//!
//! ## Protocol Sequence Diagram
//!
//! ```text
//! ┌──────┐                              ┌───────┐
//! │Client│                              │Issuer │
//! └──┬───┘                              └───┬───┘
//!    │       ┌─────────────────┐            │
//!    │       │ Issuance Phase  │            │
//!    │       └─────────────────┘            │
//!    │ 1. Generate PreIssuance(r,k)         │
//!    │    [KEPT BY CLIENT]                  │
//!    │                                      │
//!    │ 2. Create IssuanceRequest            │
//!    │    [SENT TO ISSUER]                  │
//!    │ ──────────────────────────────────>  │
//!    │                                      │ 3. Verify request
//!    │                                      │ 4. Generate IssuanceResponse
//!    │                                      │    [SENT TO CLIENT]
//!    │ <─────────────────────────────────── │
//!    │ 5. Convert PreIssuance+Response      │
//!    │    to CreditToken                    │
//!    │    [KEPT BY CLIENT]                  │
//!    │                                      │
//!    │       ┌─────────────────┐            │
//!    │       │  Spending Phase │            │
//!    │       └─────────────────┘            │
//!    │ 6. Create SpendProof                 │
//!    │    [SENT TO ISSUER]                  │
//!    │    and PreRefund                     │
//!    │    [KEPT BY CLIENT]                  │
//!    │ ──────────────────────────────────>  │
//!    │                                      │ 7. Verify SpendProof
//!    │                                      │ 8. Check nullifier
//!    │                                      │ 9. Generate Refund
//!    │                                      │    [SENT TO CLIENT]
//!    │ <─────────────────────────────────── │
//!    │ 10. Convert PreRefund+Refund         │
//!    │     to new CreditToken               │
//!    │     with remaining balance           │
//!    │     [KEPT BY CLIENT]                 │
//! ┌──┴───┐                              ┌───┴───┐
//! │Client│                              │Issuer │
//! └──────┘                              └───────┘
//! ```
//!
//! ## Overview
//!
//! This library implements the Anonymous Credit Scheme designed by Jonathan Katz
//! and Samuel Schlesinger. The system allows:
//!
//! - **Credit Issuance**: Services can issue digital credit tokens to users
//! - **Anonymous Spending**: Users can spend these credits without revealing their identity
//! - **Double-Spend Prevention**: The system prevents credits from being used multiple times
//! - **Privacy-Preserving Refunds**: Unspent credits can be refunded without compromising user privacy
//!
//! The implementation uses BBS signatures and zero-knowledge proofs to ensure both
//! security and privacy, making it suitable for integration into web services and distributed systems.
//!
//! ## Key Concepts
//!
//! - **Issuer**: The service that creates and validates credit tokens (typically your backend server)
//! - **Client**: The user who receives, holds, and spends credit tokens (typically your users)
//! - **Credit Token**: A cryptographic token representing a certain amount of credits
//! - **Nullifier**: A unique identifier used to prevent double-spending
//!
//! ## Privacy Considerations
//!
//! - **Request Context (`ctx`)**: The `ctx` value is revealed in the clear during every
//!   spend operation and persists unchanged across the entire issuance-spend-refund chain.
//!   If each issuance uses a distinct `ctx` (e.g., a per-user or per-session identifier),
//!   then every subsequent spend and refund becomes linkable back to that original issuance
//!   and to each other, completely defeating the anonymity guarantees of the scheme. To
//!   preserve unlinkability, assign the same `ctx` to all clients within a given context
//!   (e.g., per-service or per-epoch), or use `Scalar::ZERO` when context binding is not
//!   needed. See the `ctx` parameter on `PrivateKey::issue()` for more details.
//!
//! - **Nullifier Storage**: The issuer **must** record every nullifier from verified spend
//!   proofs and reject any proof whose nullifier has been seen before. Failure to do so
//!   allows double-spending. Nullifier storage must be persistent and the record-then-refund
//!   sequence must be atomic to prevent race conditions.
//!
//! ## Quick Start
//!
//! ```
//! use anonymous_credit_tokens::ristretto255::{Params, PreIssuance, PrivateKey};
//! use curve25519_dalek::Scalar;
//! use rand_core::OsRng;
//!
//! // Setup: create system parameters and issuer keypair
//! let params = Params::new("example-org", "payment-api", "production", "2024-01-15").unwrap();
//! let private_key = PrivateKey::random(OsRng);
//!
//! // Issuance: client requests 100 credits
//! let preissuance = PreIssuance::random(OsRng);
//! let request = preissuance.request(&params, OsRng);
//! let response = private_key
//!     .issue::<128>(&params, &request, Scalar::from(100u64), Scalar::ZERO, OsRng)
//!     .unwrap();
//! let token = preissuance
//!     .to_credit_token::<128>(&params, private_key.public(), &request, &response)
//!     .unwrap();
//!
//! // Spending: client spends 30 credits
//! let (spend_proof, prerefund) = token.prove_spend::<128>(&params, Scalar::from(30u64), OsRng).unwrap();
//!
//! // Server verifies proof and checks nullifier, then issues refund
//! let refund = private_key.refund(&params, &spend_proof, Scalar::ZERO, OsRng).unwrap();
//!
//! // Client constructs new token with 70 credits remaining
//! let new_token = prerefund
//!     .to_credit_token(&params, &spend_proof, &refund, private_key.public())
//!     .unwrap();
//! ```
//!
//! ## References
//!
//! - [IETF CFRG Draft](https://datatracker.ietf.org/doc/draft-schlesinger-cfrg-act/) - The cryptographic protocol specification
//! - [IETF Privacy Pass Draft](https://datatracker.ietf.org/doc/draft-schlesinger-privacypass-act/) - The deployment specification
//!
//! See the README.md file for comprehensive integration guidance.

use crate::ciphersuite::{CborError, Ciphersuite};
use ciborium::value::Value;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE, ristretto::RistrettoBasepointTable,
    traits::VartimeMultiscalarMul, RistrettoPoint,
};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

// Re-export types used in the public API so consumers don't need to depend
// on curve25519-dalek or rand_core directly.
pub use curve25519_dalek::Scalar;
pub use rand_core::{self, CryptoRngCore};

pub use crate::ciphersuite::{ErrorCode, ErrorMsg, ParamsError};

// ── Type aliases ──────────────────────────────────────────────────────────

/// The private key of the issuer, used to issue and refund credit tokens.
pub type PrivateKey = crate::protocol::PrivateKey<Ristretto255>;

/// The public key of the issuer, used to verify credit tokens.
pub type PublicKey = crate::protocol::PublicKey<Ristretto255>;

/// System parameters that define the cryptographic setup for the anonymous credentials scheme.
pub type Params = crate::protocol::Params<Ristretto255>;

/// Client state maintained during the issuance protocol.
pub type PreIssuance = crate::protocol::PreIssuance<Ristretto255>;

/// A request sent by the client to the issuer to obtain a credit token.
pub type IssuanceRequest = crate::protocol::IssuanceRequest<Ristretto255>;

/// The issuer's response to a client's issuance request.
pub type IssuanceResponse = crate::protocol::IssuanceResponse<Ristretto255>;

/// The credit token used to store and spend anonymous credits.
pub type CreditToken = crate::protocol::CreditToken<Ristretto255>;

/// A zero-knowledge proof that allows spending credits anonymously.
pub type SpendProof<const L: usize> = crate::protocol::SpendProof<Ristretto255, L>;

/// Client state maintained during the refund protocol.
pub type PreRefund = crate::protocol::PreRefund<Ristretto255>;

/// The issuer's response to a spending proof, used to create a new credit token.
pub type Refund = crate::protocol::Refund<Ristretto255>;

// ── Ciphersuite definition ────────────────────────────────────────────────

/// The Ristretto255 ciphersuite for the Anonymous Credit Token protocol.
///
/// This zero-sized type selects Ristretto255 (curve25519) as the underlying
/// elliptic curve group, with BLAKE3 for hashing and transcript operations.
#[derive(Debug, Clone, Copy, Zeroize)]
pub struct Ristretto255;

impl Ciphersuite for Ristretto255 {
    type Point = RistrettoPoint;
    type Scalar = Scalar;
    type ParamPoint = RistrettoBasepointTable;
    type CompressedPoint = [u8; 32];
    type ScalarBytes = [u8; 32];

    const PROTOCOL_VERSION: &'static [u8] = b"curve25519-ristretto anonymous-credits v1.0";

    // ── Scalar operations ────────────────────────────────────────────

    fn scalar_to_u128(s: &Scalar) -> Option<u128> {
        let bytes = s.as_bytes();
        let value = u128::from_le_bytes(bytes[..16].try_into().unwrap());
        bytes[16..].iter().all(|&b| b == 0).then_some(value)
    }

    fn scalar_from_u128(v: u128) -> Scalar {
        Scalar::from(v)
    }

    fn scalar_fits_in_bits<const L: usize>(s: &Scalar) -> bool {
        let bytes = s.as_bytes();
        let full_byte = L / 8;
        let rem_bits = L % 8;
        let mut any_high = 0u8;
        if rem_bits != 0 {
            any_high |= bytes[full_byte] >> rem_bits;
        }
        let start = full_byte + usize::from(rem_bits != 0);
        for &b in &bytes[start..32] {
            any_high |= b;
        }
        bool::from(any_high.ct_eq(&0))
    }

    fn bits_of<const L: usize>(s: Scalar) -> [Choice; L] {
        let bytes = s.as_bytes();
        let mut result = [Choice::from(0u8); L];
        result.iter_mut().enumerate().for_each(|(i, elem)| {
            *elem = Choice::from((bytes[i / 8] >> (i % 8)) & 1);
        });
        result
    }

    fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
        *s.as_bytes()
    }

    fn scalar_invert(s: &Scalar) -> Scalar {
        s.invert()
    }

    // ── Point operations ─────────────────────────────────────────────

    fn generator_mul(s: &Scalar) -> RistrettoPoint {
        RISTRETTO_BASEPOINT_TABLE * s
    }

    fn multiscalar_mul(scalars: &[Scalar], points: &[RistrettoPoint]) -> RistrettoPoint {
        RistrettoPoint::vartime_multiscalar_mul(scalars.iter(), points.iter())
    }

    // ── ParamPoint operations ────────────────────────────────────────

    fn to_param_point(p: &RistrettoPoint) -> RistrettoBasepointTable {
        RistrettoBasepointTable::create(p)
    }

    fn param_to_point(pp: &RistrettoBasepointTable) -> RistrettoPoint {
        pp.basepoint()
    }

    fn param_mul(pp: &RistrettoBasepointTable, s: &Scalar) -> RistrettoPoint {
        pp * s
    }

    // ── Transcript operations ────────────────────────────────────────

    fn challenge_from_hasher(hasher: blake3::Hasher) -> Scalar {
        let mut reader = hasher.finalize_xof();
        let mut output = [0u8; 64];
        reader.fill(&mut output);
        Scalar::from_bytes_mod_order_wide(&output)
    }

    fn hash_to_point(domain_separator: &str, seed: &[u8], counter: u32) -> RistrettoPoint {
        let mut hasher = blake3::Hasher::new();
        let ds_bytes = domain_separator.as_bytes();
        hasher.update(&(ds_bytes.len() as u64).to_be_bytes());
        hasher.update(ds_bytes);
        hasher.update(&(seed.len() as u64).to_be_bytes());
        hasher.update(seed);
        hasher.update(&(4u64).to_be_bytes());
        hasher.update(&counter.to_le_bytes());
        let mut uniform_bytes = [0u8; 64];
        hasher.finalize_xof().fill(&mut uniform_bytes);
        RistrettoPoint::from_uniform_bytes(&uniform_bytes)
    }

    fn encode_point_for_transcript(point: &RistrettoPoint) -> [u8; 32] {
        *point.compress().as_bytes()
    }

    // ── CBOR operations ──────────────────────────────────────────────

    fn encode_point_cbor(point: &RistrettoPoint) -> Value {
        Value::Bytes(point.compress().as_bytes().to_vec())
    }

    fn decode_point_cbor(value: &Value) -> Result<RistrettoPoint, CborError> {
        match value {
            Value::Bytes(bytes) if bytes.len() == 32 => {
                use curve25519_dalek::ristretto::CompressedRistretto;
                CompressedRistretto::from_slice(bytes)
                    .unwrap()
                    .decompress()
                    .ok_or(CborError::InvalidValue("invalid Ristretto point"))
            }
            _ => Err(CborError::InvalidStructure(
                "expected 32-byte array for point",
            )),
        }
    }

    fn encode_scalar_cbor(scalar: &Scalar) -> Value {
        Value::Bytes(scalar.as_bytes().to_vec())
    }

    fn decode_scalar_cbor(value: &Value) -> Result<Scalar, CborError> {
        match value {
            Value::Bytes(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(bytes);
                Option::from(Scalar::from_canonical_bytes(arr))
                    .ok_or(CborError::InvalidValue("non-canonical scalar encoding"))
            }
            _ => Err(CborError::InvalidStructure(
                "expected 32-byte array for scalar",
            )),
        }
    }
}

// ── Public convenience functions ──────────────────────────────────────────

/// Attempts to convert a Scalar to a u128 value.
///
/// This function attempts to extract a u128 value from a Scalar. Since Scalars can
/// represent values much larger than a u128, this function returns None if the
/// Scalar represents a value outside the u128 range.
///
/// # Arguments
///
/// * `scalar` - The Scalar value to convert to a u128
///
/// # Returns
///
/// * `Some(u128)` - The u128 value if the Scalar is within the u128 range
/// * `None` - If the Scalar value is too large to fit in a u128
///
/// # Example
///
/// ```
/// use anonymous_credit_tokens::ristretto255::scalar_to_u128;
///
/// let scalar = 42u128.into();
/// assert_eq!(scalar_to_u128(&scalar), Some(42));
/// ```
pub fn scalar_to_u128(scalar: &Scalar) -> Option<u128> {
    Ristretto255::scalar_to_u128(scalar)
}

/// Converts a Scalar back to a credit amount, validating that it fits within L bits.
///
/// This implements the `ScalarToCredit` function from the spec (Section 3.8).
/// The scalar must represent a value in the range `[0, 2^L)`. Values outside
/// this range are rejected with [`ErrorCode::InvalidAmount`].
///
/// # Type Parameters
///
/// * `L` - The bit-length for credit values. Must be `<= 128`.
///
/// # Arguments
///
/// * `scalar` - The Scalar value to convert to a credit amount
///
/// # Returns
///
/// * `Ok(u128)` - The credit amount if the scalar is within the valid range
/// * `Err(ErrorCode::InvalidAmount)` - If the scalar does not fit in L bits or u128
///
/// # Example
///
/// ```
/// use anonymous_credit_tokens::ristretto255::{scalar_to_credit, credit_to_scalar};
///
/// let scalar = credit_to_scalar::<128>(100).unwrap();
/// assert_eq!(scalar_to_credit::<128>(&scalar), Ok(100));
///
/// // With a smaller L, large values are rejected
/// let big = credit_to_scalar::<128>(1000).unwrap();
/// assert!(scalar_to_credit::<8>(&big).is_err()); // 1000 >= 2^8
/// ```
pub fn scalar_to_credit<const L: usize>(scalar: &Scalar) -> Result<u128, ErrorCode> {
    crate::protocol::scalar_to_credit::<Ristretto255, L>(scalar)
}

/// Converts a credit amount to a Scalar, validating that it is within the valid range.
///
/// This implements the `CreditToScalar` function from the spec (Section 3.8).
/// The amount must satisfy `0 <= amount < 2^L`. For L < 128, values >= 2^L are
/// rejected. For L >= 128, all u128 values are valid.
///
/// Note: zero is a valid spend amount (re-anonymization), though `issue()` separately
/// enforces `c > 0` for issuance.
///
/// # Arguments
///
/// * `amount` - The credit amount as a u128
///
/// # Returns
///
/// * `Ok(Scalar)` - The scalar representation of the amount
/// * `Err(ErrorCode::InvalidAmount)` - If the amount exceeds 2^L - 1
///
/// # Example
///
/// ```
/// use anonymous_credit_tokens::ristretto255::credit_to_scalar;
///
/// let scalar = credit_to_scalar::<128>(100).unwrap();
/// let zero = credit_to_scalar::<128>(0).unwrap(); // valid for spend amounts
/// ```
pub fn credit_to_scalar<const L: usize>(amount: u128) -> Result<Scalar, ErrorCode> {
    crate::protocol::credit_to_scalar::<Ristretto255, L>(amount)
}

#[cfg(test)]
mod tests;
