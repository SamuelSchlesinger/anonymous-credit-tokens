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

#![deny(missing_docs)]
#![forbid(unsafe_code)]

//! # Anonymous Credit Tokens (Publicly Verifiable)
//!
//! A Rust implementation of a publicly verifiable Anonymous Credit Scheme using
//! BLS12-381 pairings. Unlike the privately verifiable variant (which uses
//! Ristretto255), anyone with the issuer's public key can verify spend proofs.
//!
//! ## WARNING
//!
//! This cryptography is experimental and unaudited. Do not use in production
//! environments without thorough security review.
//!
//! ## Key Difference from Private Variant
//!
//! In the private variant, only the issuer (with private key `x`) can verify
//! spend proofs. In this public variant, pairing-based verification allows
//! anyone with the issuer's public key (in G2) to verify proofs.
//!
//! ## Quick Start
//!
//! ```
//! use anonymous_credit_tokens_public::{Params, PreIssuance, PrivateKey, Scalar, scalar_zero};
//! use rand_core::OsRng;
//!
//! // Setup
//! let params = Params::new("example-org", "payment-api", "production", "2024-01-15");
//! let private_key = PrivateKey::random(OsRng);
//!
//! // Issuance: client requests 100 credits
//! let preissuance = PreIssuance::random(OsRng);
//! let request = preissuance.request(&params, OsRng);
//! let response = private_key
//!     .issue::<128>(&params, &request, Scalar::from(100u64), scalar_zero(), OsRng)
//!     .unwrap();
//! let token = preissuance
//!     .to_credit_token::<128>(&params, private_key.public(), &request, &response)
//!     .unwrap();
//!
//! // Spending: client spends 30 credits
//! let (spend_proof, prerefund) = token.prove_spend::<128>(&params, Scalar::from(30u64), OsRng).unwrap();
//!
//! // Anyone with the public key can verify the spend proof
//! let refund = private_key.refund(&params, &spend_proof, scalar_zero(), OsRng).unwrap();
//!
//! // Client constructs new token with 70 credits remaining
//! let new_token = prerefund
//!     .to_credit_token(&params, &spend_proof, &refund, private_key.public())
//!     .unwrap();
//! ```

use bls12_381::{pairing, G1Affine, G1Projective, G2Affine};
use ff::Field;
use group::Group;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use std::ops::Neg;

mod transcript;
use transcript::Transcript;

pub mod cbor;

/// The BLS12-381 scalar field element type.
pub use bls12_381::Scalar;
/// Re-export rand_core for convenience.
pub use rand_core::{self, CryptoRngCore};

/// Returns the zero scalar.
pub fn scalar_zero() -> Scalar {
    Scalar::zero()
}

/// Converts a u128 value to a BLS12-381 Scalar.
pub fn scalar_from_u128(v: u128) -> Scalar {
    let lo = (v & 0xFFFF_FFFF_FFFF_FFFF) as u64;
    let hi = (v >> 64) as u64;
    // 2^64 mod r as a scalar
    let two_64 = Scalar::from(u64::MAX) + Scalar::one();
    Scalar::from(lo) + Scalar::from(hi) * two_64
}

/// Attempts to convert a Scalar to a u128 value.
///
/// Returns `None` if the scalar represents a value outside the u128 range.
pub fn scalar_to_u128(scalar: &Scalar) -> Option<u128> {
    let bytes = scalar.to_bytes();
    // BLS12-381 Scalar::to_bytes() returns little-endian
    // Check that the high bytes (indices 16..32) are zero
    if bytes[16..].iter().any(|&b| b != 0) {
        return None;
    }
    // Read the low 128 bits (little-endian bytes 0..16)
    let value = u128::from_le_bytes(bytes[..16].try_into().expect("slice with incorrect length"));
    Some(value)
}

/// The private key of the issuer, used to issue and refund credit tokens.
#[derive(Debug, Clone)]
pub struct PrivateKey {
    /// The secret scalar used in cryptographic operations
    x: Scalar,
    /// The corresponding public key
    public: PublicKey,
}

impl PrivateKey {
    /// Creates a new random private key.
    pub fn random(mut rng: impl CryptoRngCore) -> Self {
        let x = Scalar::random(&mut rng);
        let public = PublicKey {
            w: G2Affine::from(G2Affine::generator() * x),
        };
        PrivateKey { x, public }
    }

    /// Returns a reference to the public key.
    pub fn public(&self) -> &PublicKey {
        &self.public
    }
}

/// The public key of the issuer (in G2 for pairing-based verification).
///
/// Anyone with this key can verify spend proofs — this is the key difference
/// from the privately verifiable variant.
#[derive(Debug, Clone)]
pub struct PublicKey {
    /// The public point in G2
    w: G2Affine,
}

/// System parameters for the anonymous credit scheme.
#[derive(Clone)]
pub struct Params {
    /// Generator points in G1 for commitment schemes
    h1: G1Projective,
    /// Second generator
    h2: G1Projective,
    /// Third generator
    h3: G1Projective,
    /// Fourth generator for request_context
    h4: G1Projective,
    /// Cached transcript base hasher state
    transcript_base: blake3::Hasher,
}

impl std::fmt::Debug for Params {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Params")
            .field("h1", &"G1Projective")
            .field("h2", &"G1Projective")
            .field("h3", &"G1Projective")
            .field("h4", &"G1Projective")
            .finish()
    }
}

impl Params {
    /// Generates random system parameters (primarily for testing).
    pub fn random(mut rng: impl CryptoRngCore) -> Self {
        Self::from_points(
            G1Projective::random(&mut rng),
            G1Projective::random(&mut rng),
            G1Projective::random(&mut rng),
            G1Projective::random(&mut rng),
        )
    }

    /// Creates system parameters using a structured domain separator.
    pub fn new(organization: &str, service: &str, deployment_id: &str, version: &str) -> Self {
        assert!(
            !organization.contains(':'),
            "organization must not contain ':'"
        );
        assert!(!service.contains(':'), "service must not contain ':'");
        assert!(
            !deployment_id.contains(':'),
            "deployment_id must not contain ':'"
        );
        assert!(!version.contains(':'), "version must not contain ':'");

        let domain_separator = format!(
            "ACT-public-v1:{}:{}:{}:{}",
            organization, service, deployment_id, version
        );

        let mut hasher = blake3::Hasher::new();
        let domain_separator_bytes = domain_separator.as_bytes();
        hasher.update(&(domain_separator_bytes.len() as u64).to_be_bytes());
        hasher.update(domain_separator_bytes);
        let seed = hasher.finalize();

        let h1 = Self::hash_to_g1(&domain_separator, seed.as_bytes(), 0);
        let h2 = Self::hash_to_g1(&domain_separator, seed.as_bytes(), 1);
        let h3 = Self::hash_to_g1(&domain_separator, seed.as_bytes(), 2);
        let h4 = Self::hash_to_g1(&domain_separator, seed.as_bytes(), 3);

        Self::from_points(h1, h2, h3, h4)
    }

    /// Hash to G1 using BLAKE3 XOF -> 64 bytes -> scalar -> G1 generator mul.
    fn hash_to_g1(domain_separator: &str, seed: &[u8], counter: u32) -> G1Projective {
        let mut hasher = blake3::Hasher::new();
        let domain_separator_bytes = domain_separator.as_bytes();
        hasher.update(&(domain_separator_bytes.len() as u64).to_be_bytes());
        hasher.update(domain_separator_bytes);
        hasher.update(&(seed.len() as u64).to_be_bytes());
        hasher.update(seed);
        hasher.update(&(4u64).to_be_bytes());
        hasher.update(&counter.to_le_bytes());

        let mut uniform_bytes = [0u8; 64];
        let mut output_reader = hasher.finalize_xof();
        output_reader.fill(&mut uniform_bytes);

        let s = Scalar::from_bytes_wide(&uniform_bytes);
        G1Projective::generator() * s
    }

    fn from_points(
        h1: G1Projective,
        h2: G1Projective,
        h3: G1Projective,
        h4: G1Projective,
    ) -> Self {
        let transcript_base = Transcript::base_hasher(&h1, &h2, &h3, &h4);
        Params {
            h1,
            h2,
            h3,
            h4,
            transcript_base,
        }
    }
}

/// Client state maintained during the issuance protocol.
#[derive(Debug, Clone)]
pub struct PreIssuance {
    /// A random scalar used as a blinding factor
    r: Scalar,
    /// A random scalar representing the credit token's identifier
    k: Scalar,
}

/// A request sent by the client to the issuer to obtain a credit token.
#[derive(Debug, Clone)]
pub struct IssuanceRequest {
    /// A commitment to the client's identifier and blinding factor
    big_k: G1Projective,
    /// A challenge value
    gamma: Scalar,
    /// A response value for the identifier commitment
    k_bar: Scalar,
    /// A response value for the blinding factor
    r_bar: Scalar,
}

/// The credit token.
#[derive(Debug, Clone)]
pub struct CreditToken {
    /// BBS+ signature component
    a: G1Projective,
    /// Random scalar used in the BBS+ signature
    e: Scalar,
    /// Token's unique identifier (nullifier)
    k: Scalar,
    /// Blinding factor
    r: Scalar,
    /// Credit amount
    c: Scalar,
    /// Request context
    ctx: Scalar,
}

impl PreIssuance {
    /// Creates a new random `PreIssuance` state.
    pub fn random(mut rng: impl CryptoRngCore) -> Self {
        PreIssuance {
            r: Scalar::random(&mut rng),
            k: Scalar::random(&mut rng),
        }
    }

    /// Creates an issuance request.
    pub fn request(&self, params: &Params, mut rng: impl CryptoRngCore) -> IssuanceRequest {
        let big_k = params.h2 * self.k + params.h3 * self.r;

        let k_prime = Scalar::random(&mut rng);
        let r_prime = Scalar::random(&mut rng);
        let k1 = params.h2 * k_prime + params.h3 * r_prime;

        let gamma = Transcript::with(params, b"request", |transcript| {
            transcript.add_elements([&big_k, &k1].into_iter());
        });

        let k_bar = k_prime + self.k * gamma;
        let r_bar = r_prime + self.r * gamma;

        IssuanceRequest {
            big_k,
            gamma,
            k_bar,
            r_bar,
        }
    }

    /// Constructs a credit token from the issuer's response.
    ///
    /// Verification uses pairing check instead of DLEQ proof:
    /// `e(A, W) == e(X_A - e*A, G2_gen)`
    pub fn to_credit_token<const L: usize>(
        &self,
        params: &Params,
        public: &PublicKey,
        request: &IssuanceRequest,
        response: &IssuanceResponse,
    ) -> Result<CreditToken, ErrorCode> {
        const { assert!(L > 0 && L <= 128, "L must be in 1..=128") };

        if bool::from(response.a.is_identity()) {
            return Err(ErrorCode::InvalidProof);
        }

        if !scalar_fits_in_bits::<L>(&response.c) {
            return Err(ErrorCode::InvalidAmount);
        }

        let x_a = G1Projective::generator()
            + params.h1 * response.c
            + params.h4 * response.ctx
            + request.big_k;

        // Pairing check: e(A, W) == e(X_A - e*A, G2_gen)
        let a_affine = G1Affine::from(response.a);
        let rhs_point = G1Affine::from(x_a - response.a * response.e);
        let lhs = pairing(&a_affine, &public.w);
        let rhs = pairing(&rhs_point, &G2Affine::generator());

        if lhs != rhs {
            return Err(ErrorCode::InvalidProof);
        }

        Ok(CreditToken {
            a: response.a,
            e: response.e,
            r: self.r,
            k: self.k,
            c: response.c,
            ctx: response.ctx,
        })
    }
}

/// The issuer's response to a client's issuance request.
///
/// No DLEQ proof needed — the client verifies via pairing check.
#[derive(Debug, Clone)]
pub struct IssuanceResponse {
    /// The BBS+ signature's main component
    a: G1Projective,
    /// A random scalar used in the BBS+ signature
    e: Scalar,
    /// The amount of credits being issued
    c: Scalar,
    /// The request context
    ctx: Scalar,
}

impl PrivateKey {
    /// Issues credits to a client.
    pub fn issue<const L: usize>(
        &self,
        params: &Params,
        request: &IssuanceRequest,
        c: Scalar,
        ctx: Scalar,
        mut rng: impl CryptoRngCore,
    ) -> Result<IssuanceResponse, ErrorCode> {
        const { assert!(L > 0 && L <= 128, "L must be in 1..=128") };

        if c == Scalar::zero() || !scalar_fits_in_bits::<L>(&c) {
            return Err(ErrorCode::InvalidAmount);
        }

        if bool::from(request.big_k.is_identity()) {
            return Err(ErrorCode::InvalidProof);
        }

        // Verify the client's ZK proof
        let k1 = (params.h2 * request.k_bar + params.h3 * request.r_bar)
            - request.big_k * request.gamma;

        let gamma = Transcript::with(params, b"request", |transcript| {
            transcript.add_elements([&request.big_k, &k1].into_iter());
        });

        if gamma != request.gamma {
            return Err(ErrorCode::InvalidProof);
        }

        // Create BBS+ signature
        let e = Scalar::random(&mut rng);
        let x_a = G1Projective::generator() + params.h1 * c + params.h4 * ctx + request.big_k;
        let a = x_a * (e + self.x).invert().unwrap();

        Ok(IssuanceResponse { a, e, c, ctx })
    }
}

/// A zero-knowledge proof for spending credits.
///
/// In the publicly verifiable variant, this includes `a_bar` so that
/// verification can use pairings instead of the private key.
#[derive(Debug, Clone)]
pub struct SpendProof<const L: usize> {
    /// The nullifier
    k: Scalar,
    /// The request context
    ctx: Scalar,
    /// The amount being spent
    s: Scalar,
    /// Blinded signature component
    a_prime: G1Projective,
    /// Blinded token component
    b_bar: G1Projective,
    /// Prover-computed a_bar for public verification
    a_bar: G1Projective,
    /// Commitments for binary decomposition
    com: [G1Projective; L],
    /// Challenge value
    gamma: Scalar,
    /// Response values
    e_bar: Scalar,
    /// Response for signature transformation
    r2_bar: Scalar,
    /// Response for signature transformation
    r3_bar: Scalar,
    /// Response for credit amount
    c_bar: Scalar,
    /// Response for blinding factor
    r_bar: Scalar,
    /// Response for range proof (bit 0, value 0)
    w00: Scalar,
    /// Response for range proof (bit 0, value 1)
    w01: Scalar,
    /// Challenge values for each bit
    gamma0: [Scalar; L],
    /// Response values for range proof bit commitments
    z: [[Scalar; 2]; L],
    /// Response for credit identifier
    k_bar: Scalar,
    /// Response for range proof sum commitment
    s_bar: Scalar,
}

impl<const L: usize> SpendProof<L> {
    const _ASSERT: () = assert!(L > 0 && L <= 128, "L must be in 1..=128");

    /// Returns the nullifier.
    #[allow(clippy::let_unit_value)]
    pub fn nullifier(&self) -> Scalar {
        let _ = Self::_ASSERT;
        self.k
    }

    /// Returns the request context.
    pub fn context(&self) -> Scalar {
        self.ctx
    }

    /// Returns the spend amount.
    pub fn charge(&self) -> Scalar {
        self.s
    }
}

impl PrivateKey {
    /// Processes a spend proof and issues a refund token.
    ///
    /// Verification uses pairing check for a_bar instead of computing `A' * x`.
    pub fn refund<const L: usize>(
        &self,
        params: &Params,
        spend_proof: &SpendProof<L>,
        t: Scalar,
        mut rng: impl CryptoRngCore,
    ) -> Result<Refund, ErrorCode> {
        const { assert!(L > 0 && L <= 128, "L must be in 1..=128") };

        if bool::from(spend_proof.a_prime.is_identity()) {
            return Err(ErrorCode::InvalidProof);
        }

        // Pairing check: e(A', W) == e(a_bar, G2_gen)
        let pairing_ok = pairing(&G1Affine::from(spend_proof.a_prime), &self.public.w)
            == pairing(&G1Affine::from(spend_proof.a_bar), &G2Affine::generator());
        if !pairing_ok {
            return Err(ErrorCode::InvalidProof);
        }
        let a_bar = spend_proof.a_bar;

        let big_h1 = G1Projective::generator()
            + params.h2 * spend_proof.k
            + params.h4 * spend_proof.ctx;

        // a1 = A'*e_bar + B_bar*r2_bar - A_bar*gamma
        let a1 = spend_proof.a_prime * spend_proof.e_bar
            + spend_proof.b_bar * spend_proof.r2_bar
            + a_bar * spend_proof.gamma.neg();

        // a2 = B_bar*r3_bar + H1*c_bar + H3*r_bar - H1'*gamma
        let a2 = spend_proof.b_bar * spend_proof.r3_bar
            + big_h1 * spend_proof.gamma.neg()
            + params.h1 * spend_proof.c_bar
            + params.h3 * spend_proof.r_bar;

        let h1_point = params.h1;
        let h3_point = params.h3;
        let com0 = spend_proof.com[0];
        let com0_minus_h1 = com0 - h1_point;
        let gamma01_0 = spend_proof.gamma - spend_proof.gamma0[0];
        let mut big_c_prime = [[G1Projective::identity(); 2]; L];

        big_c_prime[0][0] = params.h2 * spend_proof.w00
            + h3_point * spend_proof.z[0][0]
            + com0 * spend_proof.gamma0[0].neg();
        big_c_prime[0][1] = params.h2 * spend_proof.w01
            + h3_point * spend_proof.z[0][1]
            + com0_minus_h1 * gamma01_0.neg();

        #[allow(clippy::needless_range_loop)]
        for j in 1..L {
            let com_j = spend_proof.com[j];
            let com_j_minus_h1 = com_j - h1_point;
            let gamma01_j = spend_proof.gamma - spend_proof.gamma0[j];
            big_c_prime[j][0] = h3_point * spend_proof.z[j][0]
                + com_j * spend_proof.gamma0[j].neg();
            big_c_prime[j][1] = h3_point * spend_proof.z[j][1]
                + com_j_minus_h1 * gamma01_j.neg();
        }

        let k_prime = pow2_weighted_sum(&spend_proof.com);
        let com_ = params.h1 * spend_proof.s + k_prime;
        let big_c = h1_point * spend_proof.c_bar.neg()
            + params.h2 * spend_proof.k_bar
            + h3_point * spend_proof.s_bar
            + com_ * spend_proof.gamma.neg();

        let gamma = Transcript::with(params, b"spend", |transcript| {
            transcript.add_scalar(&spend_proof.k);
            transcript.add_scalar(&spend_proof.ctx);
            transcript.add_elements([&spend_proof.a_prime, &spend_proof.b_bar, &spend_proof.a_bar].into_iter());
            transcript.add_elements([&a1, &a2].into_iter());
            transcript.add_elements(spend_proof.com.iter());
            for c_prime in big_c_prime.iter() {
                transcript.add_elements(c_prime.iter());
            }
            transcript.add_element(&big_c);
        });

        if gamma != spend_proof.gamma {
            return Err(ErrorCode::InvalidProof);
        }

        // Validate partial return amount
        if !scalar_fits_in_bits::<L>(&t) {
            return Err(ErrorCode::InvalidAmount);
        }
        if !scalar_fits_in_bits::<L>(&spend_proof.s) {
            return Err(ErrorCode::InvalidAmount);
        }
        let t_val = scalar_to_u128(&t).ok_or(ErrorCode::InvalidAmount)?;
        let s_val = scalar_to_u128(&spend_proof.s).ok_or(ErrorCode::InvalidAmount)?;
        if t_val > s_val {
            return Err(ErrorCode::InvalidAmount);
        }

        let e = Scalar::random(&mut rng);

        let x_a = G1Projective::generator()
            + k_prime
            + params.h1 * t
            + params.h4 * spend_proof.ctx;
        let a = x_a * (e + self.x).invert().unwrap();

        Ok(Refund { a, e, t })
    }
}

/// Client state maintained during the refund protocol.
#[derive(Debug, Clone)]
pub struct PreRefund {
    /// A random blinding factor
    r: Scalar,
    /// A random identifier
    k: Scalar,
    /// Remaining balance after spending
    m: Scalar,
    /// Request context
    ctx: Scalar,
}

/// Computes power-of-two weighted sum using Horner's method.
fn pow2_weighted_sum(points: &[G1Projective]) -> G1Projective {
    let n = points.len();
    debug_assert!(n > 0);
    let mut result = points[n - 1];
    for j in (0..n - 1).rev() {
        result = result.double() + points[j];
    }
    result
}

/// Computes power-of-two weighted sum of scalars using Horner's method.
fn pow2_weighted_scalar_sum(scalars: &[Scalar]) -> Scalar {
    let n = scalars.len();
    debug_assert!(n > 0);
    let mut result = scalars[n - 1];
    for j in (0..n - 1).rev() {
        result = result + result + scalars[j];
    }
    result
}

/// Checks whether all bits at positions >= L are zero (constant-time).
fn scalar_fits_in_bits<const L: usize>(s: &Scalar) -> bool {
    // BLS12-381 Scalar::to_bytes() returns little-endian, 32 bytes.
    let le_bytes = s.to_bytes();

    let full_byte = L / 8;
    let rem_bits = L % 8;
    let mut any_high = 0u8;
    if rem_bits != 0 {
        any_high |= le_bytes[full_byte] >> rem_bits;
    }
    let start = full_byte + usize::from(rem_bits != 0);
    for &b in &le_bytes[start..32] {
        any_high |= b;
    }
    bool::from(any_high.ct_eq(&0))
}

/// Decomposes a scalar into its binary representation as `Choice` values.
fn bits_of<const L: usize>(s: Scalar) -> [Choice; L] {
    // BLS12-381 Scalar::to_bytes() returns little-endian
    let le_bytes = s.to_bytes();

    let mut result = [Choice::from(0u8); L];
    result.iter_mut().enumerate().for_each(|(i, result_elem)| {
        *result_elem = Choice::from((le_bytes[i / 8] >> (i % 8)) & 1);
    });
    result
}

impl CreditToken {
    /// Returns the nullifier contained within this token.
    pub fn nullifier(&self) -> Scalar {
        self.k
    }

    /// Returns the number of credits contained within this token.
    pub fn credits(&self) -> Scalar {
        self.c
    }

    /// Creates a spend proof.
    ///
    /// In the publicly verifiable variant, this also computes `a_bar` which
    /// allows verification via pairings instead of the private key.
    pub fn prove_spend<const L: usize>(
        &self,
        params: &Params,
        s: Scalar,
        mut rng: impl CryptoRngCore,
    ) -> Result<(SpendProof<L>, PreRefund), ErrorCode> {
        const { assert!(L > 0 && L <= 128, "L must be in 1..=128") };

        if !scalar_fits_in_bits::<L>(&s) {
            return Err(ErrorCode::InvalidAmount);
        }
        if !scalar_fits_in_bits::<L>(&self.c) {
            return Err(ErrorCode::InvalidAmount);
        }
        if !scalar_fits_in_bits::<L>(&(self.c - s)) {
            return Err(ErrorCode::InvalidAmount);
        }

        let r1 = Scalar::random(&mut rng);
        let r2 = Scalar::random(&mut rng);
        let c_prime = Scalar::random(&mut rng);
        let r_prime = Scalar::random(&mut rng);
        let e_prime = Scalar::random(&mut rng);
        let r2_prime = Scalar::random(&mut rng);
        let r3_prime = Scalar::random(&mut rng);

        let b = G1Projective::generator()
            + params.h1 * self.c
            + params.h2 * self.k
            + params.h3 * self.r
            + params.h4 * self.ctx;
        let a_prime = self.a * (r1 * r2);
        let b_bar = b * r1;

        // Compute a_bar = b_bar * r2 - a_prime * self.e
        // This equals A' * x (the verifier would need x to compute this
        // in the private variant, but here the prover provides it)
        let a_bar = b_bar * r2 - a_prime * self.e;

        let r3 = r1.invert().unwrap();
        let a1 = a_prime * e_prime + b_bar * r2_prime;
        let a2 = b_bar * r3_prime + params.h1 * c_prime + params.h3 * r_prime;

        let i = bits_of::<L>(self.c - s);

        let k_star = Scalar::random(&mut rng);
        let mut s_i = [Scalar::zero(); L];
        for s_val in s_i.iter_mut() {
            *s_val = Scalar::random(&mut rng);
        }

        let mut com = [G1Projective::identity(); L];
        let h1_point = params.h1;
        let h1_bit_0 = G1Projective::conditional_select(
            &G1Projective::identity(),
            &h1_point,
            i[0],
        );
        com[0] = h1_bit_0 + params.h2 * k_star + params.h3 * s_i[0];
        for j in 1..L {
            let h1_bit = G1Projective::conditional_select(
                &G1Projective::identity(),
                &h1_point,
                i[j],
            );
            com[j] = h1_bit + params.h3 * s_i[j];
        }
        let mut big_c_prime = [[G1Projective::identity(); 2]; L];

        let k0_prime = Scalar::random(&mut rng);
        let mut s_i_prime = [Scalar::zero(); L];
        for s_prime in s_i_prime.iter_mut() {
            *s_prime = Scalar::random(&mut rng);
        }
        let mut gamma_i = [Scalar::zero(); L];
        for gamma in gamma_i.iter_mut() {
            *gamma = Scalar::random(&mut rng);
        }
        let w0 = Scalar::random(&mut rng);
        let mut z = [Scalar::zero(); L];
        for z_val in z.iter_mut() {
            *z_val = Scalar::random(&mut rng);
        }

        // Compute C'[0][0] and C'[0][1]
        let h2_k0_h3_s0 = params.h2 * k0_prime + params.h3 * s_i_prime[0];
        let h1_gamma0 = params.h1 * gamma_i[0];
        let h1_i0_gamma = G1Projective::conditional_select(
            &G1Projective::identity(),
            &h1_gamma0,
            i[0],
        );
        let h2_diff0 = params.h2 * (w0 - k_star * gamma_i[0]);
        let h3_diff0 = params.h3 * (z[0] - s_i[0] * gamma_i[0]);
        let diff0 = h2_diff0 + h3_diff0 - h1_i0_gamma;

        big_c_prime[0][0] = G1Projective::conditional_select(
            &diff0,
            &h2_k0_h3_s0,
            !i[0],
        );
        big_c_prime[0][1] = G1Projective::conditional_select(
            &h2_k0_h3_s0,
            &(diff0 + h1_gamma0),
            !i[0],
        );

        // Compute C'[j][0] and C'[j][1] for j = 1..L-1
        for j in 1..L {
            let h3_s_j = params.h3 * s_i_prime[j];
            let h1_gamma = params.h1 * gamma_i[j];
            let h3_diff = params.h3 * (z[j] - s_i[j] * gamma_i[j]);
            let h1_i_gamma = G1Projective::conditional_select(
                &G1Projective::identity(),
                &h1_gamma,
                i[j],
            );
            let diff = h3_diff - h1_i_gamma;

            big_c_prime[j][0] = G1Projective::conditional_select(
                &diff,
                &h3_s_j,
                !i[j],
            );
            big_c_prime[j][1] = G1Projective::conditional_select(
                &h3_s_j,
                &(diff + h1_gamma),
                !i[j],
            );
        }

        let r_star = pow2_weighted_scalar_sum(&s_i);
        let k_prime_rand = Scalar::random(&mut rng);
        let s_prime_rand = Scalar::random(&mut rng);
        let c_ = params.h1 * c_prime.neg()
            + params.h2 * k_prime_rand
            + params.h3 * s_prime_rand;

        let gamma = Transcript::with(params, b"spend", |transcript| {
            transcript.add_scalar(&self.k);
            transcript.add_scalar(&self.ctx);
            transcript.add_elements([&a_prime, &b_bar, &a_bar].into_iter());
            transcript.add_elements([&a1, &a2].into_iter());
            transcript.add_elements(com.iter());
            for c_prime in big_c_prime.iter() {
                transcript.add_elements(c_prime.iter());
            }
            transcript.add_element(&c_);
        });

        let e_bar = gamma.neg() * self.e + e_prime;
        let r2_bar = gamma * r2 + r2_prime;
        let r3_bar = gamma * r3 + r3_prime;
        let c_bar = gamma.neg() * self.c + c_prime;
        let r_bar = gamma.neg() * self.r + r_prime;

        let mut gamma00 = [Scalar::zero(); L];
        gamma00[0] = Scalar::conditional_select(
            &gamma_i[0],
            &(gamma - gamma_i[0]),
            !i[0],
        );
        let w00 = Scalar::conditional_select(
            &w0,
            &(gamma00[0] * k_star + k0_prime),
            !i[0],
        );
        let w01 = Scalar::conditional_select(
            &((gamma - gamma00[0]) * k_star + k0_prime),
            &w0,
            !i[0],
        );
        let mut z00 = [[Scalar::zero(); 2]; L];
        z00[0][0] = Scalar::conditional_select(
            &z[0],
            &(gamma00[0] * s_i[0] + s_i_prime[0]),
            !i[0],
        );
        z00[0][1] = Scalar::conditional_select(
            &((gamma - gamma00[0]) * s_i[0] + s_i_prime[0]),
            &z[0],
            !i[0],
        );
        for j in 1..L {
            gamma00[j] = Scalar::conditional_select(
                &gamma_i[j],
                &(gamma - gamma_i[j]),
                !i[j],
            );
            z00[j][0] = Scalar::conditional_select(
                &z[j],
                &(gamma00[j] * s_i[j] + s_i_prime[j]),
                !i[j],
            );
            z00[j][1] = Scalar::conditional_select(
                &((gamma - gamma00[j]) * s_i[j] + s_i_prime[j]),
                &z[j],
                !i[j],
            );
        }
        let k_bar = gamma * k_star + k_prime_rand;
        let s_bar = gamma * r_star + s_prime_rand;

        let prerefund = PreRefund {
            k: k_star,
            r: r_star,
            m: self.c - s,
            ctx: self.ctx,
        };

        Ok((
            SpendProof {
                k: self.k,
                ctx: self.ctx,
                s,
                a_prime,
                b_bar,
                a_bar,
                com,
                gamma,
                e_bar,
                r2_bar,
                r3_bar,
                c_bar,
                r_bar,
                w00,
                w01,
                gamma0: gamma00,
                z: z00,
                k_bar,
                s_bar,
            },
            prerefund,
        ))
    }
}

/// The issuer's refund response.
///
/// No DLEQ proof needed — the client verifies via pairing check.
#[derive(Debug, Clone)]
pub struct Refund {
    /// BBS+ signature component
    a: G1Projective,
    /// Random scalar
    e: Scalar,
    /// Credits returned
    t: Scalar,
}

impl Refund {
    /// Returns the partial credit return amount.
    pub fn partial_return(&self) -> Scalar {
        self.t
    }
}

impl PreRefund {
    /// Constructs a new credit token from the refund response.
    ///
    /// Verification uses pairing check instead of DLEQ proof.
    pub fn to_credit_token<const L: usize>(
        &self,
        params: &Params,
        spend_proof: &SpendProof<L>,
        refund: &Refund,
        public_key: &PublicKey,
    ) -> Result<CreditToken, ErrorCode> {
        const { assert!(L > 0 && L <= 128, "L must be in 1..=128") };

        if bool::from(refund.a.is_identity()) {
            return Err(ErrorCode::InvalidProof);
        }

        let x_a = G1Projective::generator()
            + pow2_weighted_sum(&spend_proof.com)
            + params.h1 * refund.t
            + params.h4 * self.ctx;

        // Pairing check: e(A, W) == e(X_A - e*A, G2_gen)
        let a_affine = G1Affine::from(refund.a);
        let rhs_point = G1Affine::from(x_a - refund.a * refund.e);
        let lhs = pairing(&a_affine, &public_key.w);
        let rhs = pairing(&rhs_point, &G2Affine::generator());

        if lhs != rhs {
            return Err(ErrorCode::InvalidProof);
        }

        if !scalar_fits_in_bits::<L>(&refund.t) {
            return Err(ErrorCode::InvalidAmount);
        }

        let new_balance = self.m + refund.t;

        if !scalar_fits_in_bits::<L>(&new_balance) {
            return Err(ErrorCode::InvalidAmount);
        }

        Ok(CreditToken {
            a: refund.a,
            e: refund.e,
            k: self.k,
            r: self.r,
            c: new_balance,
            ctx: self.ctx,
        })
    }
}

/// Converts a Scalar to a credit amount, validating range.
pub fn scalar_to_credit<const L: usize>(scalar: &Scalar) -> Result<u128, ErrorCode> {
    const { assert!(L > 0 && L <= 128, "L must be in 1..=128") };
    if !scalar_fits_in_bits::<L>(scalar) {
        return Err(ErrorCode::InvalidAmount);
    }
    scalar_to_u128(scalar).ok_or(ErrorCode::InvalidAmount)
}

/// Converts a credit amount to a Scalar, validating range.
pub fn credit_to_scalar<const L: usize>(amount: u128) -> Result<Scalar, ErrorCode> {
    const { assert!(L > 0 && L <= 128, "L must be in 1..=128") };
    if L < 128 && amount >= (1u128 << L) {
        return Err(ErrorCode::InvalidAmount);
    }
    Ok(scalar_from_u128(amount))
}

/// Error codes for the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    /// Proof verification failed
    InvalidProof = 1,
    /// Double-spend attempt detected
    NullifierReuse = 2,
    /// Request format is invalid
    MalformedRequest = 3,
    /// Credit amount exceeds maximum
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

/// An error message.
#[derive(Debug, Clone)]
pub struct ErrorMsg {
    /// The error code.
    pub error_code: ErrorCode,
    /// A human-readable message.
    pub error_message: String,
}

impl std::fmt::Display for ErrorMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.error_code, self.error_message)
    }
}

impl std::error::Error for ErrorMsg {}

/// Publicly verify a spend proof using only the issuer's public key.
///
/// This is the core new capability of the publicly verifiable variant.
/// Anyone with the public key can verify that a spend proof is valid.
pub fn verify_spend_proof<const L: usize>(
    params: &Params,
    public_key: &PublicKey,
    spend_proof: &SpendProof<L>,
) -> Result<(), ErrorCode> {
    const { assert!(L > 0 && L <= 128, "L must be in 1..=128") };

    if bool::from(spend_proof.a_prime.is_identity()) {
        return Err(ErrorCode::InvalidProof);
    }

    // Pairing check: e(A', W) == e(a_bar, G2_gen)
    let pairing_ok = pairing(&G1Affine::from(spend_proof.a_prime), &public_key.w)
        == pairing(&G1Affine::from(spend_proof.a_bar), &G2Affine::generator());
    if !pairing_ok {
        return Err(ErrorCode::InvalidProof);
    }
    let a_bar = spend_proof.a_bar;

    let big_h1 = G1Projective::generator()
        + params.h2 * spend_proof.k
        + params.h4 * spend_proof.ctx;

    let a1 = spend_proof.a_prime * spend_proof.e_bar
        + spend_proof.b_bar * spend_proof.r2_bar
        + a_bar * spend_proof.gamma.neg();

    let a2 = spend_proof.b_bar * spend_proof.r3_bar
        + big_h1 * spend_proof.gamma.neg()
        + params.h1 * spend_proof.c_bar
        + params.h3 * spend_proof.r_bar;

    let h1_point = params.h1;
    let h3_point = params.h3;
    let com0 = spend_proof.com[0];
    let com0_minus_h1 = com0 - h1_point;
    let gamma01_0 = spend_proof.gamma - spend_proof.gamma0[0];
    let mut big_c_prime = [[G1Projective::identity(); 2]; L];

    big_c_prime[0][0] = params.h2 * spend_proof.w00
        + h3_point * spend_proof.z[0][0]
        + com0 * spend_proof.gamma0[0].neg();
    big_c_prime[0][1] = params.h2 * spend_proof.w01
        + h3_point * spend_proof.z[0][1]
        + com0_minus_h1 * gamma01_0.neg();

    #[allow(clippy::needless_range_loop)]
    for j in 1..L {
        let com_j = spend_proof.com[j];
        let com_j_minus_h1 = com_j - h1_point;
        let gamma01_j = spend_proof.gamma - spend_proof.gamma0[j];
        big_c_prime[j][0] = h3_point * spend_proof.z[j][0]
            + com_j * spend_proof.gamma0[j].neg();
        big_c_prime[j][1] = h3_point * spend_proof.z[j][1]
            + com_j_minus_h1 * gamma01_j.neg();
    }

    let k_prime = pow2_weighted_sum(&spend_proof.com);
    let com_ = params.h1 * spend_proof.s + k_prime;
    let big_c = h1_point * spend_proof.c_bar.neg()
        + params.h2 * spend_proof.k_bar
        + h3_point * spend_proof.s_bar
        + com_ * spend_proof.gamma.neg();

    let gamma = Transcript::with(params, b"spend", |transcript| {
        transcript.add_scalar(&spend_proof.k);
        transcript.add_scalar(&spend_proof.ctx);
        transcript.add_elements([&spend_proof.a_prime, &spend_proof.b_bar, &spend_proof.a_bar].into_iter());
        transcript.add_elements([&a1, &a2].into_iter());
        transcript.add_elements(spend_proof.com.iter());
        for c_prime in big_c_prime.iter() {
            transcript.add_elements(c_prime.iter());
        }
        transcript.add_element(&big_c);
    });

    if gamma != spend_proof.gamma {
        return Err(ErrorCode::InvalidProof);
    }

    Ok(())
}

#[cfg(test)]
mod tests;
