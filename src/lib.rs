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

//! # Anonymous Credit Tokens
//!
//! A Rust implementation of Anonymous Credit Tokens (ACT), following
//! draft-schlesinger-cfrg-act: a privacy-preserving credit scheme in which an
//! issuer grants tokens holding credits that clients spend anonymously.
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
//!    │                                      │    (c credits, context ctx)
//!    │ <─────────────────────────────────── │
//!    │ 5. Convert PreIssuance+Response      │
//!    │    to CreditToken                    │
//!    │    [KEPT BY CLIENT]                  │
//!    │                                      │
//!    │       ┌─────────────────┐            │
//!    │       │  Spending Phase │            │
//!    │       └─────────────────┘            │
//!    │ 6. Create SpendProof for spend s     │
//!    │    and optional top-up a             │
//!    │    [SENT TO ISSUER]                  │
//!    │    and PreRefund                     │
//!    │    [KEPT BY CLIENT]                  │
//!    │ ──────────────────────────────────>  │
//!    │                                      │ 7. Verify SpendProof
//!    │                                      │ 8. Check nullifier
//!    │                                      │ 9. Generate Refund with
//!    │                                      │    partial refund t
//!    │ <─────────────────────────────────── │
//!    │ 10. Convert PreRefund+Refund         │
//!    │     to new CreditToken with          │
//!    │     balance c - s + a + t            │
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
//! - **Top-Ups**: An issuer-authorized top-up amount can be added to the balance
//!   during a spend, bound as a public value in the spend proof
//! - **Partial Refunds**: The issuer can return part of the spent amount when
//!   issuing the refund
//! - **Double-Spend Prevention**: The system prevents credits from being used multiple times
//! - **Privacy-Preserving Refunds**: Unspent credits are refunded without compromising user privacy
//!
//! Credit values lie in the range `[0, 3^D)` and range proofs use a base-3 digit
//! decomposition, which minimizes proof size for this proof system.
//!
//! ## Key Concepts
//!
//! - **Issuer**: The service that creates and validates credit tokens (typically your backend server)
//! - **Client**: The user who receives, holds, and spends credit tokens (typically your users)
//! - **Credit Token**: A cryptographic token representing a certain amount of credits,
//!   bound to a request context `ctx`
//! - **Nullifier**: A unique identifier used to prevent double-spending
//!
//! ## Usage Examples
//!
//! See the README.md file for comprehensive usage examples and integration guidance.

use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::RistrettoBasepointTable};
use group::Group;
use rand_core::CryptoRngCore;
use sigma_proofs::LinearRelation;
use zeroize::{ZeroizeOnDrop, Zeroizing};

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidIssuanceRequestProof,
    InvalidIssuanceResponseProof,
    InvalidRefundProof,
    IdentityPointError,
    InvalidClientSpendProof,
    AmountTooBigError,
    ScalarOutOfRangeError,
    /// A spend, top-up, or balance amount is outside [0, 3^D).
    InvalidAmount,
    /// A partial refund amount exceeds max(0, s - a) or 3^D - 1.
    InvalidRefundAmount,
}

// Note: double-spend detection is the caller's responsibility (see
// PrivateKey::refund), so this library never raises a double-spend error; the
// caller records nullifiers and rejects reuse with its own error type.

/// The number of base-3 digits used in the range proof decomposition.
///
/// The ACT specification treats D as a deployment parameter with
/// `D <= MAX_DIGITS = 80` (the largest D for which 3^D < 2^127, so every
/// credit amount fits the u128 encoding while keeping 3^D + 2^128 far below
/// the group order; see the specification's security considerations on
/// amount validation and modular wraparound).
///
/// This branch fixes D = 8 — balances in [0, 6561) — sized for
/// rate-limiting-style deployments (MoLE). The spend proof is linear in D
/// (192*D + 450 bytes on the wire), so small D keeps presentations inside
/// ordinary HTTP header budgets: 1,986 bytes at D = 8 versus 15,810 at
/// D = 80. Making D a const generic so one build supports several
/// deployments remains TODO.
pub const D: usize = 8;

/// The maximum credit amount representable in a token: 3^D - 1.
pub const MAX_CREDITS: u128 = 3u128.pow(D as u32) - 1;

pub mod wire;

/// Attempts to convert a Scalar to a u128 value.
///
/// This function attempts to extract a u128 value from a Scalar. Since Scalars can
/// represent values much larger than a u128, this function returns None if the
/// Scalar represents a value outside the u128 range.
///
/// # Example
///
/// ```
/// use anonymous_credit_tokens::scalar_to_u128;
///
/// let scalar = 42u128.into();
/// assert_eq!(scalar_to_u128(&scalar), Some(42));
/// ```
pub fn scalar_to_u128(scalar: &Scalar) -> Option<u128> {
    // Get the low 128 bits of the scalar
    let bytes = scalar.as_bytes();
    let value = u128::from_le_bytes(bytes[..16].try_into().expect("slice with incorrect length"));

    // Check if the scalar is within u128 range and the high bits are zero
    bytes[16..].iter().all(|&b| b == 0).then_some(value)
}

/// Decomposes a scalar value into its base-3 representation.
///
/// This implements TritDecompose from the ACT specification: D rounds of
/// short division by 3 over the 32-byte little-endian scalar encoding. The
/// quotient in each step is computed with a multiply-and-shift
/// (`(acc * 683) >> 11`, exact for `acc < 2048`), so the algorithm contains
/// no data-dependent branches, divisions, or table lookups.
///
/// The input must represent an integer in `[0, 3^D)`; higher-order residue
/// is discarded.
fn trits_of(s: &Scalar) -> [Scalar; D] {
    let mut bytes = *s.as_bytes();
    let mut result = [Scalar::ZERO; D];

    for digit in result.iter_mut() {
        let mut r: u32 = 0;
        for i in (0..32).rev() {
            let acc = r * 256 + bytes[i] as u32; // 0 <= acc < 768
            let q = (acc * 683) >> 11; // floor(acc / 3)
            bytes[i] = q as u8;
            r = acc - 3 * q; // acc mod 3
        }
        *digit = Scalar::from(r as u64);
    }

    result
}

/// Returns the powers of three `3^0, ..., 3^(D-1)` as scalars.
fn pow3_scalars() -> [Scalar; D] {
    let mut out = [Scalar::ZERO; D];
    let mut acc: u128 = 1;
    for o in out.iter_mut() {
        *o = Scalar::from(acc);
        acc *= 3;
    }
    out
}

/// Reduces a domain separation tag longer than 255 bytes per RFC 9380
/// Section 5.3.3, so that arbitrarily long ACT domain separators are accepted
/// rather than panicking.
fn normalize_dst_sha512(dst: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha512};
    if dst.len() <= 255 {
        dst.to_vec()
    } else {
        Sha512::new()
            .chain_update(b"H2C-OVERSIZED-DST-")
            .chain_update(dst)
            .finalize()
            .to_vec()
    }
}

/// expand_message_xmd from Section 5.3.1 of RFC 9380, instantiated
/// with SHA-512. Domain separation tags longer than 255 bytes are reduced per
/// Section 5.3.3.
fn expand_message_xmd_sha512(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
    use sha2::{Digest, Sha512};
    const B_IN_BYTES: usize = 64;
    const S_IN_BYTES: usize = 128;
    let ell = len_in_bytes.div_ceil(B_IN_BYTES);
    assert!(ell <= 255 && len_in_bytes <= 65535);
    let dst = normalize_dst_sha512(dst);
    let mut dst_prime = dst.to_vec();
    dst_prime.push(dst.len() as u8);

    let b0 = Sha512::new()
        .chain_update([0u8; S_IN_BYTES])
        .chain_update(msg)
        .chain_update((len_in_bytes as u16).to_be_bytes())
        .chain_update([0u8])
        .chain_update(&dst_prime)
        .finalize();
    let mut b_i = Sha512::new()
        .chain_update(b0)
        .chain_update([1u8])
        .chain_update(&dst_prime)
        .finalize();
    let mut out = b_i.to_vec();
    for i in 2..=ell {
        let xored: Vec<u8> = b0.iter().zip(b_i.iter()).map(|(x, y)| x ^ y).collect();
        b_i = Sha512::new()
            .chain_update(&xored)
            .chain_update([i as u8])
            .chain_update(&dst_prime)
            .finalize();
        out.extend_from_slice(&b_i);
    }
    out.truncate(len_in_bytes);
    out
}

/// hash_to_ristretto255 from Appendix B of RFC 9380, instantiated with
/// expand_message_xmd using SHA-512, as required by the
/// ACT(ristretto255, SHAKE128) suite.
fn hash_to_ristretto255(msg: &[u8], dst: &[u8]) -> RistrettoPoint {
    let uniform_bytes = expand_message_xmd_sha512(msg, dst, 64);
    RistrettoPoint::from_uniform_bytes(&uniform_bytes.try_into().expect("64 bytes"))
}

/// The ACT Fiat-Shamir protocol identifier, from the ACT(ristretto255,
/// SHAKE128) suite. draft-irtf-cfrg-sigma-protocols Section 5 makes the
/// protocol identifier the caller's responsibility, and the Fiat-Shamir draft
/// standardizes no ristretto255 ciphersuite, so ACT defines its own. The value
/// is zero-padded to the 64 bytes the Fiat-Shamir transform requires.
fn act_protocol_id() -> [u8; 64] {
    const LABEL: &[u8] = b"ACT-v1_SchnorrProof_Shake128_Ristretto255";
    let mut id = [0u8; 64];
    id[..LABEL.len()].copy_from_slice(LABEL);
    id
}

/// Builds a session identifier from the domain separator, a label, and
/// protocol-bound scalars, as specified for each proof in the draft.
fn session(params: &Params, label: &[u8], scalars: &[&Scalar]) -> Vec<u8> {
    let mut out = params.domain_separator.clone();
    out.extend_from_slice(label);
    for s in scalars {
        out.extend_from_slice(s.as_bytes());
    }
    out
}

/// The private key of the issuer, used to issue and refund credit tokens.
///
/// This key should be kept secure, as it allows the owner to create new tokens
/// and process refunds. The private key includes the corresponding public key
/// that can be shared with clients.
#[derive(ZeroizeOnDrop, Debug, Clone)]
pub struct PrivateKey {
    /// The secret scalar used in cryptographic operations
    x: Scalar,
    /// The corresponding public key that can be shared with clients
    #[zeroize(skip)]
    public: PublicKey,
}

impl PrivateKey {
    /// Creates a new random private key using the provided cryptographically secure random number generator.
    ///
    /// # Example
    ///
    /// ```
    /// use anonymous_credit_tokens::PrivateKey;
    /// use rand_core::OsRng;
    ///
    /// let private_key = PrivateKey::random(OsRng);
    /// ```
    pub fn random(mut rng: impl CryptoRngCore) -> Self {
        let x = Scalar::random(&mut rng);
        let public = PublicKey {
            w: RistrettoPoint::generator() * x,
        };
        PrivateKey { x, public }
    }

    /// Returns a reference to the public key associated with this private key.
    pub fn public(&self) -> &PublicKey {
        &self.public
    }
}

/// The public key of the issuer, used to verify credit tokens.
///
/// This key is shared with clients so they can validate tokens and create spending proofs.
/// It contains a Ristretto point that serves as the public component of the issuer's keypair.
#[derive(Debug, Clone)]
pub struct PublicKey {
    /// The public point derived from the secret scalar in the private key
    w: RistrettoPoint,
}

/// System parameters that define the cryptographic setup for the anonymous credentials scheme.
///
/// These parameters are used in various cryptographic operations throughout the protocol.
/// They must be generated deterministically from a domain separator that uniquely identifies
/// your deployment.
#[derive(Clone)]
pub struct Params {
    /// The domain separator this instance was derived from
    domain_separator: Vec<u8>,
    /// First generator point used in commitment schemes (credit values)
    h1: RistrettoBasepointTable,
    /// Second generator point used in commitment schemes (nullifiers)
    h2: RistrettoBasepointTable,
    /// Third generator point used in commitment schemes (blinding factors)
    h3: RistrettoBasepointTable,
    /// Fourth generator point, binding the request context
    h4: RistrettoBasepointTable,
}

impl PartialEq for Params {
    fn eq(&self, other: &Params) -> bool {
        self.domain_separator == other.domain_separator
            && self.h1.basepoint() == other.h1.basepoint()
            && self.h2.basepoint() == other.h2.basepoint()
            && self.h3.basepoint() == other.h3.basepoint()
            && self.h4.basepoint() == other.h4.basepoint()
    }
}

impl std::fmt::Debug for Params {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Params")
            .field(
                "domain_separator",
                &String::from_utf8_lossy(&self.domain_separator),
            )
            .finish_non_exhaustive()
    }
}

impl Params {
    /// Creates system parameters using a structured domain separator.
    ///
    /// This method creates deterministic parameters based on deployment-specific
    /// information, ensuring cryptographic isolation between different services.
    ///
    /// # Arguments
    ///
    /// * `organization` - Unique identifier for the organization (e.g., "example-corp")
    /// * `service` - The specific service or application name (e.g., "payment-api")
    /// * `deployment_id` - The deployment environment (e.g., "production", "staging")
    /// * `version` - Version date in YYYY-MM-DD format (e.g., "2024-01-15")
    ///
    /// # Example
    ///
    /// ```
    /// use anonymous_credit_tokens::Params;
    ///
    /// let params = Params::new(
    ///     "example-corp",
    ///     "payment-api",
    ///     "production",
    ///     "2024-01-15"
    /// );
    /// ```
    pub fn new(organization: &str, service: &str, deployment_id: &str, version: &str) -> Self {
        let domain_separator = format!(
            "ACT-v1:{}:{}:{}:{}",
            organization, service, deployment_id, version
        );
        Self::from_domain_separator(domain_separator.as_bytes())
    }

    /// Creates system parameters from a raw domain separator, implementing
    /// the SetGenerators function from the ACT specification.
    ///
    /// The generators H1..H4 are derived independently via hash_to_ristretto255
    /// with distinct inputs, and re-derived with an incremented counter in the
    /// (cryptographically unreachable) event of a collision, so that no party
    /// knows discrete-logarithm relations among them.
    ///
    /// The `domain_separator` SHOULD follow the structured format produced by
    /// [`Params::new`].
    pub fn from_domain_separator(domain_separator: &[u8]) -> Self {
        // The specification requires a non-empty domain separator and warns
        // against generic or unstructured separators, which would collapse the
        // cryptographic isolation between deployments.
        assert!(
            !domain_separator.is_empty(),
            "domain separator must be non-empty"
        );
        let dst = [b"HashToGroup-", domain_separator].concat();
        let g0 = RistrettoPoint::generator();
        let mut h = [g0; 4];
        let mut counter: u32 = 0;
        loop {
            let mut encodings = std::collections::HashSet::new();
            encodings.insert(g0.compress().to_bytes());
            for p in h.iter() {
                encodings.insert(p.compress().to_bytes());
            }
            if encodings.len() == 5 {
                break;
            }
            assert!(counter <= 255, "generator derivation failed");
            let ctr = [counter as u8];
            h[0] = hash_to_ristretto255(&[b"GenH1", &ctr[..], domain_separator].concat(), &dst);
            h[1] = hash_to_ristretto255(&[b"GenH2", &ctr[..], domain_separator].concat(), &dst);
            h[2] = hash_to_ristretto255(&[b"GenH3", &ctr[..], domain_separator].concat(), &dst);
            h[3] = hash_to_ristretto255(&[b"GenH4", &ctr[..], domain_separator].concat(), &dst);
            counter += 1;
        }

        Params {
            domain_separator: domain_separator.to_vec(),
            h1: RistrettoBasepointTable::create(&h[0]),
            h2: RistrettoBasepointTable::create(&h[1]),
            h3: RistrettoBasepointTable::create(&h[2]),
            h4: RistrettoBasepointTable::create(&h[3]),
        }
    }

    /// Returns the domain separator these parameters were derived from.
    pub fn domain_separator(&self) -> &[u8] {
        &self.domain_separator
    }
}

/// Client state maintained during the issuance protocol.
///
/// This structure holds the client's secret values that are needed to complete
/// the issuance protocol and eventually construct a valid credit token. The client
/// must keep this information private during the issuance process.
#[derive(ZeroizeOnDrop, Debug, Clone)]
pub struct PreIssuance {
    /// A random scalar used as a blinding factor
    r: Scalar,
    /// A random scalar representing the credit token's identifier
    k: Scalar,
}

/// A request sent by the client to the issuer to obtain a credit token.
///
/// This contains the cryptographic commitments and proof values required for the issuer
/// to create a valid credit token while maintaining the client's privacy. The client
/// generates this request using their `PreIssuance` state.
#[derive(ZeroizeOnDrop, Debug, Clone)]
pub struct IssuanceRequest {
    /// A commitment to the client's identifier and blinding factor
    big_k: RistrettoPoint,
    /// Proof of knowledge of the client's identifier and blinding factor
    pok: Vec<u8>,
}

/// The credit token used to store and spend anonymous credits.
///
/// This token represents the client's anonymous credits. It contains the cryptographic
/// elements needed to prove ownership and spend credits without revealing the client's
/// identity. The token includes a credit value `c` and the request context `ctx` it
/// is bound to.
#[derive(ZeroizeOnDrop, Debug, Clone, PartialEq)]
pub struct CreditToken {
    /// A Ristretto point representing the BBS signature component
    a: RistrettoPoint,
    /// A random scalar used in the BBS signature
    e: Scalar,
    /// The token's unique identifier (used to prevent double-spending)
    k: Scalar,
    /// A blinding factor used to protect the token's privacy
    r: Scalar,
    /// The amount of credits available in this token
    c: Scalar,
    /// The request context this token is bound to
    ctx: Scalar,
}

impl PreIssuance {
    /// Creates a new random `PreIssuance` state to initiate the credit issuance protocol.
    ///
    /// # Security Warning
    ///
    /// It is critical to use high-quality randomness for this operation. If the `k` value
    /// collides with a previously used one, the resulting credit token could become unspendable
    /// due to double-spending prevention mechanisms.
    ///
    /// # Example
    ///
    /// ```
    /// use anonymous_credit_tokens::PreIssuance;
    /// use rand_core::OsRng;
    ///
    /// let pre_issuance = PreIssuance::random(OsRng);
    /// ```
    pub fn random(mut rng: impl CryptoRngCore) -> Self {
        PreIssuance {
            r: Scalar::random(&mut rng),
            k: Scalar::random(&mut rng),
        }
    }

    /// Creates an issuance request to obtain credits from the issuer.
    ///
    /// This method generates a zero-knowledge proof that allows the issuer to verify the
    /// integrity of the request without learning the client's secret values. The resulting
    /// request can be sent to the issuer for processing.
    ///
    /// # Example
    ///
    /// ```
    /// use anonymous_credit_tokens::{PreIssuance, Params};
    /// use rand_core::OsRng;
    ///
    /// let pre_issuance = PreIssuance::random(OsRng);
    /// let params = Params::new("test-org", "test-service", "test", "2024-01-01");
    /// let request = pre_issuance.request(&params, OsRng);
    /// ```
    pub fn request(&self, params: &Params, mut rng: impl CryptoRngCore) -> IssuanceRequest {
        // Create a commitment to the client's identifier and blinding factor
        let big_k = &params.h2 * &self.k + &params.h3 * &self.r;

        // Generate proof of knowledge of k, r for the statement: big_K = k*H2 + r*H3.
        let mut statement = LinearRelation::new();
        proofs::pedersen(
            &mut statement,
            params.h2.basepoint(),
            params.h3.basepoint(),
            big_k,
        );
        let prover = statement
            .into_nizk_with_protocol_id(&session(params, b"request", &[]), act_protocol_id())
            .unwrap();
        let witness = vec![self.k, self.r];
        let pok = prover.prove_compact(&witness, &mut rng).unwrap();

        IssuanceRequest { big_k, pok }
    }

    /// Constructs a credit token from the issuer's response to an issuance request.
    ///
    /// This method verifies the issuer's response and, if valid, creates a credit token
    /// that the client can use to spend credits. The `ctx` value is the request context
    /// agreed with the issuer (derived from shared application context); the token is
    /// bound to it.
    ///
    /// # Example
    ///
    /// ```
    /// # use anonymous_credit_tokens::{PrivateKey, PreIssuance, Params};
    /// # use curve25519_dalek::Scalar;
    /// # use rand_core::OsRng;
    /// #
    /// # let private_key = PrivateKey::random(OsRng);
    /// # let public_key = private_key.public();
    /// # let pre_issuance = PreIssuance::random(OsRng);
    /// # let params = Params::new("test-org", "test-service", "test", "2024-01-01");
    /// # let request = pre_issuance.request(&params, OsRng);
    /// # let ctx = Scalar::from(7u64);
    /// # let response = private_key.issue(&params, &request, 20, ctx, OsRng).unwrap();
    /// #
    /// let credit_token = pre_issuance.to_credit_token(
    ///     &params,
    ///     public_key,
    ///     &request,
    ///     &response,
    ///     ctx,
    /// ).unwrap();
    /// ```
    pub fn to_credit_token(
        &self,
        params: &Params,
        public: &PublicKey,
        request: &IssuanceRequest,
        response: &IssuanceResponse,
        ctx: Scalar,
    ) -> Result<CreditToken, Error> {
        // Reconstruct the signature base points for verification
        let g = RistrettoPoint::generator();
        let x_a = g + &params.h1 * &response.c + &params.h4 * &ctx + request.big_k;
        let x_g = g * response.e + public.w;

        // Verify that the challenge matches the expected value
        let mut statement = LinearRelation::new();
        proofs::dleq(&mut statement, response.a, g, x_a, x_g);
        let verifier = statement
            .into_nizk_with_protocol_id(
                &session(params, b"respond", &[&response.c, &ctx]),
                act_protocol_id(),
            )
            .unwrap();
        if verifier.verify_compact(&response.pok).is_err() {
            return Err(Error::InvalidIssuanceResponseProof);
        }

        // Construct the credit token with the verified signature
        Ok(CreditToken {
            a: response.a,
            e: response.e,
            r: self.r,
            k: self.k,
            c: response.c,
            ctx,
        })
    }
}

/// The issuer's response to a client's issuance request.
///
/// This response contains the cryptographic signature components and proof
/// values that allow the client to construct a valid credit token. It includes
/// the credit amount (`c`) assigned by the issuer and the BBS signature
/// elements that authenticate this amount. The request context is not included:
/// both parties derive it from shared application context.
#[derive(ZeroizeOnDrop, Debug, Clone, PartialEq)]
pub struct IssuanceResponse {
    /// The BBS signature's main component
    a: RistrettoPoint,
    /// A random scalar used in the BBS signature
    e: Scalar,
    /// The amount of credits being issued
    c: Scalar,
    /// Proof of knowledge of correct BBS signature.
    pok: Vec<u8>,
}

impl PrivateKey {
    /// Issues credits to a client in response to their issuance request.
    ///
    /// This method verifies the client's request for legitimacy and, if valid, creates
    /// a cryptographic signature binding the specified credit amount and request context
    /// to the client's commitment.
    ///
    /// # Arguments
    ///
    /// * `params` - The system parameters
    /// * `request` - The client's issuance request
    /// * `c` - The amount of credits to issue, in `[0, 3^D)`
    /// * `ctx` - The request context scalar to bind the token to
    /// * `rng` - A cryptographically secure random number generator
    ///
    /// # Example
    ///
    /// ```
    /// # use anonymous_credit_tokens::{PrivateKey, PreIssuance, Params};
    /// # use curve25519_dalek::Scalar;
    /// # use rand_core::OsRng;
    /// #
    /// # let private_key = PrivateKey::random(OsRng);
    /// # let pre_issuance = PreIssuance::random(OsRng);
    /// # let params = Params::new("test-org", "test-service", "test", "2024-01-01");
    /// # let request = pre_issuance.request(&params, OsRng);
    /// #
    /// // Issue 20 credits to the client
    /// let ctx = Scalar::from(7u64);
    /// let response = private_key.issue(&params, &request, 20, ctx, OsRng).unwrap();
    /// ```
    pub fn issue(
        &self,
        params: &Params,
        request: &IssuanceRequest,
        c: u128,
        ctx: Scalar,
        mut rng: impl CryptoRngCore,
    ) -> Result<IssuanceResponse, Error> {
        // Validate the credit amount
        if c > MAX_CREDITS {
            return Err(Error::AmountTooBigError);
        }
        let c = Scalar::from(c);

        // Verify the client's zero-knowledge proof
        let mut statement = LinearRelation::new();
        proofs::pedersen(
            &mut statement,
            params.h2.basepoint(),
            params.h3.basepoint(),
            request.big_k,
        );
        let verifier = statement
            .into_nizk_with_protocol_id(&session(params, b"request", &[]), act_protocol_id())
            .unwrap();
        if verifier.verify_compact(&request.pok).is_err() {
            return Err(Error::InvalidIssuanceRequestProof);
        }

        // Create a BBS signature on the client's commitment, credit amount, and context
        let g = RistrettoPoint::generator();
        let e = Scalar::random(&mut rng);
        let exp = e + self.x;
        let x_a = g + &params.h1 * &c + &params.h4 * &ctx + request.big_k;
        let a = x_a * exp.invert();
        let x_g = g * exp;

        // Generate a zero-knowledge proof that the signature is valid
        let mut statement = LinearRelation::new();
        proofs::dleq(&mut statement, a, g, x_a, x_g);
        let prover = statement
            .into_nizk_with_protocol_id(
                &session(params, b"respond", &[&c, &ctx]),
                act_protocol_id(),
            )
            .unwrap();
        let witness = vec![exp];
        let pok = prover.prove_compact(&witness, &mut rng).unwrap();

        Ok(IssuanceResponse { a, e, c, pok })
    }
}

/// A zero-knowledge proof that allows spending credits anonymously.
///
/// This proof demonstrates that the client possesses a valid credit token such that
/// the new balance `c - s + a` is in `[0, 3^D)`, without revealing the token itself.
/// The proof includes a nullifier that prevents double-spending, the public spend
/// amount `s`, the public top-up amount `a`, and the request context `ctx`.
#[derive(ZeroizeOnDrop, Debug, Clone)]
pub struct SpendProof {
    /// The nullifier, uniquely identifying this spend to prevent double-spending
    k: Scalar,
    /// The amount being spent in this transaction
    s: Scalar,
    /// The top-up amount being added in this transaction (0 for a plain spend)
    a: Scalar,
    /// The request context the token is bound to
    ctx: Scalar,
    /// The blinded signature component
    a_prime: RistrettoPoint,
    /// A blinded token component
    b_bar: RistrettoPoint,
    /// Digit commitments for the base-3 decomposition of the new balance
    com: [RistrettoPoint; D],
    /// Auxiliary commitments for the ternary range proof
    t: [RistrettoPoint; D],
    /// The compact sigma protocol proof
    pok: Vec<u8>,
}

impl SpendProof {
    /// Returns the nullifier associated with this spend.
    ///
    /// The nullifier is a unique identifier for this spend that should be recorded
    /// by the issuer to prevent double-spending. If the same nullifier is seen twice,
    /// the second spend attempt should be rejected.
    pub fn nullifier(&self) -> Scalar {
        self.k
    }

    /// Returns the amount of credits being spent in this transaction.
    pub fn charge(&self) -> Scalar {
        self.s
    }

    /// Returns the top-up amount declared in this transaction.
    pub fn topup(&self) -> Scalar {
        self.a
    }

    /// Returns the request context revealed by this spend.
    pub fn context(&self) -> Scalar {
        self.ctx
    }
}

/// Builds the LinearRelation statement for the spend proof, shared between the
/// prover and the verifier.
///
/// The statement consists of `3D + 3` equations over `4D + 7` witness scalars:
///
/// 1. `A_bar = e*(-A') + r2*B_bar` (BBS signature validity)
/// 2. `H1_prime = r3*B_bar + c*(-H1) + r*(-H3)` (credential structure)
/// 3. For each digit j, three equations enforcing `d[j] in {0, 1, 2}`:
///    - opening: `Com[j] = d[j]*H1 + s[j]*H3` (digit 0 also carries `kstar*H2`)
///    - auxiliary opening: `T[j] + Com[j] = d[j]*Com[j] + rho[j]*H3`
///    - zero constraint: `T[j]*2 = d[j]*T[j] + w[j]*H3` (digit 0 also carries `k3*H2`)
/// 4. `Com_total = c*H1 + kstar*H2 + sum_j s[j]*3^j*H3` (commitment consistency),
///    where `Com_total = (s - a)*H1 + sum_j 3^j*Com[j]`.
#[allow(clippy::too_many_arguments)]
fn spend_statement(
    params: &Params,
    k: &Scalar,
    s: &Scalar,
    a: &Scalar,
    ctx: &Scalar,
    a_prime: &RistrettoPoint,
    b_bar: &RistrettoPoint,
    a_bar: &RistrettoPoint,
    com: &[RistrettoPoint; D],
    t: &[RistrettoPoint; D],
) -> LinearRelation<RistrettoPoint> {
    let g = RistrettoPoint::generator();
    let pow3 = pow3_scalars();
    let mut rel = LinearRelation::new();

    // Scalar variables, in witness order.
    let [e_var, r2_var] = rel.allocate_scalars::<2>();
    let [r3_var, c_var, r_var] = rel.allocate_scalars::<3>();
    let d_vars = rel.allocate_scalars_vec(D);
    let s_vars = rel.allocate_scalars_vec(D);
    let rho_vars = rel.allocate_scalars_vec(D);
    let w_vars = rel.allocate_scalars_vec(D);
    let [k_star_var, k3_var] = rel.allocate_scalars::<2>();

    // Element variables.
    let neg_a_prime_var = rel.allocate_element_with(-a_prime);
    let b_bar_var = rel.allocate_element_with(*b_bar);
    let a_bar_var = rel.allocate_element_with(*a_bar);
    let neg_h1_var = rel.allocate_element_with(-params.h1.basepoint());
    let neg_h3_var = rel.allocate_element_with(-params.h3.basepoint());
    let h1_prime_var = rel.allocate_element_with(g + &params.h2 * k + &params.h4 * ctx);
    let h1_var = rel.allocate_element_with(params.h1.basepoint());
    let h2_var = rel.allocate_element_with(params.h2.basepoint());
    let h3_var = rel.allocate_element_with(params.h3.basepoint());
    let com_vars = rel.allocate_elements_with(&com[..]);
    let t_vars = rel.allocate_elements_with(&t[..]);
    // T[j] + Com[j] and T[j]*2, the left-hand sides of the auxiliary opening
    // and zero constraint equations.
    let tc_values: Vec<RistrettoPoint> = (0..D).map(|j| t[j] + com[j]).collect();
    let t2_values: Vec<RistrettoPoint> = (0..D).map(|j| t[j] + t[j]).collect();
    let tc_vars = rel.allocate_elements_with(&tc_values);
    let t2_vars = rel.allocate_elements_with(&t2_values);
    let com_total = {
        let mut acc = &params.h1 * &(s - a);
        for j in 0..D {
            acc += com[j] * pow3[j];
        }
        acc
    };
    let com_total_var = rel.allocate_element_with(com_total);

    // Eq 1: A_bar = e*(-A') + r2*B_bar (rearranged BBS signature validity)
    rel.append_equation(a_bar_var, e_var * neg_a_prime_var + r2_var * b_bar_var);

    // Eq 2: H1_prime = r3*B_bar + c*(-H1) + r*(-H3) (credential structure)
    rel.append_equation(
        h1_prime_var,
        r3_var * b_bar_var + c_var * neg_h1_var + r_var * neg_h3_var,
    );

    // Eqs 3..2+3D: ternary range proof.
    // Digit 0 carries the new nullifier kstar under H2.
    rel.append_equation(
        com_vars[0],
        d_vars[0] * h1_var + k_star_var * h2_var + s_vars[0] * h3_var,
    );
    rel.append_equation(tc_vars[0], d_vars[0] * com_vars[0] + rho_vars[0] * h3_var);
    rel.append_equation(
        t2_vars[0],
        d_vars[0] * t_vars[0] + k3_var * h2_var + w_vars[0] * h3_var,
    );
    for j in 1..D {
        rel.append_equation(com_vars[j], d_vars[j] * h1_var + s_vars[j] * h3_var);
        rel.append_equation(tc_vars[j], d_vars[j] * com_vars[j] + rho_vars[j] * h3_var);
        rel.append_equation(t2_vars[j], d_vars[j] * t_vars[j] + w_vars[j] * h3_var);
    }

    // Eq 3D+3: commitment consistency.
    let mut terms = c_var * (h1_var * Scalar::ONE) + k_star_var * (h2_var * Scalar::ONE);
    for j in 0..D {
        terms = terms + s_vars[j] * (h3_var * pow3[j]);
    }
    rel.append_equation(com_total_var, terms);

    rel
}

impl PrivateKey {
    /// Processes a spend proof and issues a refund token for the remaining credits.
    ///
    /// This method validates the public amounts, verifies the spend proof, and, if
    /// valid, issues a refund for the new balance `c - s + a`, homomorphically adding
    /// the partial refund amount `t`. The refund allows the client to construct a new
    /// credit token with balance `c - s + a + t`.
    ///
    /// A non-zero top-up amount `a` in the spend proof MUST be authorized by
    /// application policy before calling this method; verifying the proof constitutes
    /// consent to grant those credits.
    ///
    /// # Security Warning
    ///
    /// This method does NOT verify that the nullifier has not been seen before. The caller
    /// MUST check that the nullifier returned by `spend_proof.nullifier()` has not been
    /// previously processed to prevent double-spending.
    ///
    /// # Arguments
    ///
    /// * `params` - The system parameters
    /// * `spend_proof` - The client's proof of valid spending
    /// * `t` - The partial refund amount, in `[0, max(0, s - a)]`
    /// * `rng` - A cryptographically secure random number generator
    ///
    /// # Example
    ///
    /// ```
    /// # use anonymous_credit_tokens::{PrivateKey, PreIssuance, Params};
    /// # use curve25519_dalek::Scalar;
    /// # use rand_core::OsRng;
    /// #
    /// # let private_key = PrivateKey::random(OsRng);
    /// # let pre_issuance = PreIssuance::random(OsRng);
    /// # let params = Params::new("test-org", "test-service", "test", "2024-01-01");
    /// # let request = pre_issuance.request(&params, OsRng);
    /// # let ctx = Scalar::from(7u64);
    /// # let response = private_key.issue(&params, &request, 20, ctx, OsRng).unwrap();
    /// # let credit_token = pre_issuance.to_credit_token(&params, private_key.public(), &request, &response, ctx).unwrap();
    /// # let (spend_proof, prerefund) = credit_token.prove_spend(&params, 10, 0, OsRng).unwrap();
    /// #
    /// // First check if we've seen this nullifier before
    /// let nullifier = spend_proof.nullifier();
    /// // ... check nullifier database
    ///
    /// // Then process the refund, returning 2 of the 10 spent credits
    /// let refund = private_key.refund(&params, &spend_proof, 2, OsRng).unwrap();
    /// ```
    pub fn refund(
        &self,
        params: &Params,
        spend_proof: &SpendProof,
        t: u128,
        mut rng: impl CryptoRngCore,
    ) -> Result<Refund, Error> {
        if spend_proof.a_prime == RistrettoPoint::identity() {
            return Err(Error::IdentityPointError);
        }

        // Validate the public amounts as integers. These checks are REQUIRED
        // for soundness: the range proof constrains the new balance only
        // modulo the group order (see the specification's security
        // considerations on amount validation and modular wraparound).
        let s = scalar_to_u128(&spend_proof.s).ok_or(Error::ScalarOutOfRangeError)?;
        let a = scalar_to_u128(&spend_proof.a).ok_or(Error::ScalarOutOfRangeError)?;
        if s > MAX_CREDITS || a > MAX_CREDITS {
            return Err(Error::InvalidAmount);
        }

        // Validate the partial refund amount: t <= max(0, s - a).
        if t > s.saturating_sub(a) {
            return Err(Error::InvalidRefundAmount);
        }
        let t = Scalar::from(t);

        // Verify the spend proof.
        let a_bar = spend_proof.a_prime * self.x;
        let statement = spend_statement(
            params,
            &spend_proof.k,
            &spend_proof.s,
            &spend_proof.a,
            &spend_proof.ctx,
            &spend_proof.a_prime,
            &spend_proof.b_bar,
            &a_bar,
            &spend_proof.com,
            &spend_proof.t,
        );
        let verifier = statement
            .into_nizk_with_protocol_id(
                &session(
                    params,
                    b"spend",
                    &[
                        &spend_proof.k,
                        &spend_proof.s,
                        &spend_proof.a,
                        &spend_proof.ctx,
                    ],
                ),
                act_protocol_id(),
            )
            .map_err(|_| Error::InvalidClientSpendProof)?;
        if verifier.verify_compact(&spend_proof.pok).is_err() {
            return Err(Error::InvalidClientSpendProof);
        }

        // Issue a refund for the new balance, adding the partial refund t
        // homomorphically.
        let pow3 = pow3_scalars();
        let k_prime = spend_proof
            .com
            .iter()
            .zip(pow3.iter())
            .map(|(com, p)| com * p)
            .fold(RistrettoPoint::identity(), |acc, x| acc + x);

        let e_star = Scalar::random(&mut rng);
        let g = RistrettoPoint::generator();
        let exp = e_star + self.x;
        let x_a_star = g + k_prime + &params.h1 * &t + &params.h4 * &spend_proof.ctx;
        let a_star = x_a_star * exp.invert();
        let x_g = g * exp;

        let mut statement = LinearRelation::new();
        proofs::dleq(&mut statement, a_star, g, x_a_star, x_g);
        let prover = statement
            .into_nizk_with_protocol_id(
                &session(params, b"refund", &[&e_star, &t, &spend_proof.ctx]),
                act_protocol_id(),
            )
            .unwrap();
        let witness = vec![exp];
        let pok = prover.prove_compact(&witness, &mut rng).unwrap();

        Ok(Refund {
            a: a_star,
            e: e_star,
            t,
            pok,
        })
    }
}

/// Client state maintained during the refund protocol.
///
/// This structure holds the client's secret values that are needed to complete
/// the refund protocol and construct a new credit token with the new balance.
/// The client must keep this information private after spending credits and while
/// awaiting a refund.
#[derive(ZeroizeOnDrop, Debug, Clone)]
pub struct PreRefund {
    /// A random blinding factor for the new credit token
    r: Scalar,
    /// A random identifier for the new credit token
    k: Scalar,
    /// The new balance after spending and top-up (before the partial refund)
    v: Scalar,
    /// The request context this spend was bound to
    ctx: Scalar,
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

    /// Returns the request context this token is bound to.
    pub fn context(&self) -> Scalar {
        self.ctx
    }

    /// Creates a zero-knowledge proof for spending credits from this token.
    ///
    /// This method generates a proof that the client possesses a valid credit token
    /// such that the new balance `c - s + a` lies in `[0, 3^D)`, without revealing
    /// the token itself. The proof includes a ternary range proof over the new
    /// balance and a nullifier to prevent double-spending.
    ///
    /// The top-up amount `a` is bound into the proof as a public value:
    /// verification fails under any other value, so the issuer authorizes the
    /// top-up by verifying the proof with it. Use `a = 0` for a plain spend.
    /// Note that `s` may exceed the token balance when the top-up covers the
    /// difference.
    ///
    /// # Arguments
    ///
    /// * `params` - The system parameters
    /// * `s` - The amount of credits to spend, in `[0, 3^D)`
    /// * `a` - The top-up amount, in `[0, 3^D)`; 0 for a plain spend
    /// * `rng` - A cryptographically secure random number generator
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// * `SpendProof` - The proof of valid spending to send to the issuer
    /// * `PreRefund` - The client's state to keep for later creating a new credit token
    ///
    /// # Example
    ///
    /// ```
    /// # use anonymous_credit_tokens::{CreditToken, PrivateKey, PreIssuance, Params};
    /// # use curve25519_dalek::Scalar;
    /// # use rand_core::OsRng;
    /// #
    /// # // Create a valid credit token with 20 credits
    /// # let private_key = PrivateKey::random(OsRng);
    /// # let pre_issuance = PreIssuance::random(OsRng);
    /// # let params = Params::new("test-org", "test-service", "test", "2024-01-01");
    /// # let request = pre_issuance.request(&params, OsRng);
    /// # let ctx = Scalar::from(7u64);
    /// # let response = private_key.issue(&params, &request, 20, ctx, OsRng).unwrap();
    /// # let credit_token = pre_issuance.to_credit_token(&params, private_key.public(), &request, &response, ctx).unwrap();
    /// #
    /// // Spend 10 credits with no top-up
    /// let (spend_proof, prerefund) = credit_token.prove_spend(&params, 10, 0, OsRng).unwrap();
    ///
    /// // Send spend_proof to the issuer and keep prerefund for later
    /// ```
    pub fn prove_spend(
        &self,
        params: &Params,
        s: u128,
        a: u128,
        rng: impl CryptoRngCore,
    ) -> Result<(SpendProof, PreRefund), Error> {
        // Validate the amounts and compute the new balance as integers.
        if s > MAX_CREDITS || a > MAX_CREDITS {
            return Err(Error::InvalidAmount);
        }
        let c = scalar_to_u128(&self.c).ok_or(Error::ScalarOutOfRangeError)?;
        // c is bounded by MAX_CREDITS in honest flow, but a corrupted or
        // crafted token could carry a larger c; use checked arithmetic so a
        // bad token is rejected rather than overflowing.
        let v = c
            .checked_add(a)
            .and_then(|ca| ca.checked_sub(s))
            .ok_or(Error::InvalidAmount)?;
        if v > MAX_CREDITS {
            return Err(Error::InvalidAmount);
        }
        let digits = trits_of(&Scalar::from(v));

        self.prove_spend_with_digits(params, Scalar::from(s), Scalar::from(a), &digits, rng)
    }

    /// Core of the spend proof generation, parameterized by the digit
    /// decomposition of the new balance. Split out so that tests can exercise
    /// the protocol with dishonest digit values.
    fn prove_spend_with_digits(
        &self,
        params: &Params,
        s: Scalar,
        a: Scalar,
        digits: &[Scalar; D],
        mut rng: impl CryptoRngCore,
    ) -> Result<(SpendProof, PreRefund), Error> {
        let pow3 = pow3_scalars();

        // Randomize the signature.
        let r1 = Scalar::random(&mut rng);
        let r2 = Scalar::random(&mut rng);
        let b = RistrettoPoint::generator()
            + &params.h1 * &self.c
            + &params.h2 * &self.k
            + &params.h3 * &self.r
            + &params.h4 * &self.ctx;
        let a_prime = self.a * (r1 * r2);
        let b_bar = b * r1;
        let r3 = r1.invert();
        let a_bar = b_bar * r2 - a_prime * self.e;

        // Create digit commitments; digit 0 carries the new nullifier k_star.
        let k_star = Scalar::random(&mut rng);
        let mut s_com = [Scalar::ZERO; D];
        for s_j in s_com.iter_mut() {
            *s_j = Scalar::random(&mut rng);
        }
        let mut com = [RistrettoPoint::identity(); D];
        com[0] = &params.h1 * &digits[0] + &params.h2 * &k_star + &params.h3 * &s_com[0];
        for j in 1..D {
            com[j] = &params.h1 * &digits[j] + &params.h3 * &s_com[j];
        }

        // Create auxiliary commitments T[j] = (d[j] - 1)*Com[j] + rho[j]*H3.
        let mut rho = [Scalar::ZERO; D];
        for rho_j in rho.iter_mut() {
            *rho_j = Scalar::random(&mut rng);
        }
        let mut t = [RistrettoPoint::identity(); D];
        for j in 0..D {
            t[j] = com[j] * (digits[j] - Scalar::ONE) + &params.h3 * &rho[j];
        }

        // Witness values for the zero constraint equations:
        // w[j] = (2 - d[j]) * ((d[j] - 1)*s[j] + rho[j]),
        // k3 = (2 - d[0]) * (d[0] - 1) * k_star.
        let two = Scalar::from(2u64);
        let mut w = [Scalar::ZERO; D];
        for j in 0..D {
            w[j] = (two - digits[j]) * ((digits[j] - Scalar::ONE) * s_com[j] + rho[j]);
        }
        let k3 = (two - digits[0]) * (digits[0] - Scalar::ONE) * k_star;

        // Build the statement and prove it.
        let statement = spend_statement(
            params, &self.k, &s, &a, &self.ctx, &a_prime, &b_bar, &a_bar, &com, &t,
        );
        let prover = statement
            .into_nizk_with_protocol_id(
                &session(params, b"spend", &[&self.k, &s, &a, &self.ctx]),
                act_protocol_id(),
            )
            .map_err(|_| Error::InvalidClientSpendProof)?;

        // The witness holds the token's long-term secrets (e, c, r) and the
        // fresh proof secrets; wrap it so the heap buffer is zeroized on drop.
        let mut witness = Zeroizing::new(Vec::with_capacity(4 * D + 7));
        witness.push(self.e);
        witness.push(r2);
        witness.push(r3);
        witness.push(self.c);
        witness.push(self.r);
        witness.extend_from_slice(&digits[..]);
        witness.extend_from_slice(&s_com);
        witness.extend_from_slice(&rho);
        witness.extend_from_slice(&w);
        witness.push(k_star);
        witness.push(k3);
        let pok = prover
            .prove_compact(&witness, &mut rng)
            .map_err(|_| Error::InvalidClientSpendProof)?;

        // The new balance and its blinding factor under the summed commitment.
        let v = digits
            .iter()
            .zip(pow3.iter())
            .map(|(d, p)| d * p)
            .fold(Scalar::ZERO, |acc, x| acc + x);
        let r_star = s_com
            .iter()
            .zip(pow3.iter())
            .map(|(s_j, p)| s_j * p)
            .fold(Scalar::ZERO, |acc, x| acc + x);

        let prerefund = PreRefund {
            k: k_star,
            r: r_star,
            v,
            ctx: self.ctx,
        };

        Ok((
            SpendProof {
                k: self.k,
                s,
                a,
                ctx: self.ctx,
                a_prime,
                b_bar,
                com,
                t,
                pok,
            },
            prerefund,
        ))
    }
}

/// The issuer's response to a spending proof, used to create a new credit token.
///
/// This response contains the cryptographic signature components needed for the client
/// to construct a new credit token with the new balance. It includes a BBS
/// signature on the new balance, the partial refund amount `t`, and proof values
/// that authenticate the response.
#[derive(ZeroizeOnDrop, Debug, Clone, PartialEq)]
pub struct Refund {
    /// The BBS signature's main component for the new credit token
    a: RistrettoPoint,
    /// A random scalar used in the BBS signature
    e: Scalar,
    /// The partial refund amount added homomorphically by the issuer
    t: Scalar,
    /// Proof of knowledge of correct BBS signature.
    pok: Vec<u8>,
}

impl Refund {
    /// Returns the partial refund amount granted by the issuer.
    pub fn amount(&self) -> Scalar {
        self.t
    }
}

impl PreRefund {
    /// Constructs a new credit token from the refund response.
    ///
    /// This method verifies the issuer's refund response and, if valid, creates a new
    /// credit token with balance `c - s + a + t`. This completes the spending protocol
    /// by providing the client with a new token for their unspent credits.
    ///
    /// # Arguments
    ///
    /// * `params` - The system parameters
    /// * `spend_proof` - The original spending proof sent to the issuer
    /// * `refund` - The issuer's refund response
    /// * `public_key` - The issuer's public key
    ///
    /// # Example
    ///
    /// ```
    /// # use anonymous_credit_tokens::{PrivateKey, PreIssuance, Params};
    /// # use curve25519_dalek::Scalar;
    /// # use rand_core::OsRng;
    /// #
    /// # let private_key = PrivateKey::random(OsRng);
    /// # let public_key = private_key.public();
    /// # let pre_issuance = PreIssuance::random(OsRng);
    /// # let params = Params::new("test-org", "test-service", "test", "2024-01-01");
    /// # let request = pre_issuance.request(&params, OsRng);
    /// # let ctx = Scalar::from(7u64);
    /// # let response = private_key.issue(&params, &request, 20, ctx, OsRng).unwrap();
    /// # let credit_token = pre_issuance.to_credit_token(&params, public_key, &request, &response, ctx).unwrap();
    /// # let (spend_proof, prerefund) = credit_token.prove_spend(&params, 10, 0, OsRng).unwrap();
    /// # let refund = private_key.refund(&params, &spend_proof, 0, OsRng).unwrap();
    /// #
    /// // Construct the new credit token with the new balance
    /// let new_credit_token = prerefund.to_credit_token(
    ///     &params,
    ///     &spend_proof,
    ///     &refund,
    ///     public_key
    /// ).unwrap();
    /// ```
    pub fn to_credit_token(
        &self,
        params: &Params,
        spend_proof: &SpendProof,
        refund: &Refund,
        public_key: &PublicKey,
    ) -> Result<CreditToken, Error> {
        // Validate the refund amount and the new balance as integers.
        let t = scalar_to_u128(&refund.t).ok_or(Error::ScalarOutOfRangeError)?;
        if t > MAX_CREDITS {
            return Err(Error::InvalidRefundAmount);
        }
        let v = scalar_to_u128(&self.v).ok_or(Error::ScalarOutOfRangeError)?;
        // Use checked arithmetic: a corrupted PreRefund could carry a v larger
        // than MAX_CREDITS, which must be rejected rather than wrapping.
        if v.checked_add(t).is_none_or(|vt| vt > MAX_CREDITS) {
            return Err(Error::InvalidRefundAmount);
        }

        // Reconstruct the summed commitment to the new balance.
        let pow3 = pow3_scalars();
        let g = RistrettoPoint::generator();
        let k_prime = spend_proof
            .com
            .iter()
            .zip(pow3.iter())
            .map(|(com, p)| com * p)
            .fold(RistrettoPoint::identity(), |acc, x| acc + x);
        // Reconstruct against the context bound in the client's own state, so
        // that pairing this PreRefund with a spend proof or refund from a
        // different context fails verification rather than silently minting an
        // unspendable token.
        let x_a = g + k_prime + &params.h1 * &refund.t + &params.h4 * &self.ctx;
        let x_g = g * refund.e + public_key.w;

        // Verify the issuer's proof.
        let mut statement = LinearRelation::new();
        proofs::dleq(&mut statement, refund.a, g, x_a, x_g);
        let verifier = statement
            .into_nizk_with_protocol_id(
                &session(params, b"refund", &[&refund.e, &refund.t, &self.ctx]),
                act_protocol_id(),
            )
            .unwrap();
        if verifier.verify_compact(&refund.pok).is_err() {
            return Err(Error::InvalidRefundProof);
        }

        // The client now has a new credit token
        Ok(CreditToken {
            a: refund.a,
            e: refund.e,
            k: self.k,
            r: self.r,
            c: self.v + refund.t,
            ctx: self.ctx,
        })
    }
}

/// Proofs of knowledge used in this protocol.
mod proofs {
    use group::prime::PrimeGroup;
    use sigma_proofs::LinearRelation;

    /// Relation used to prove knowledge of (k0, k1) such that R = k0\*P + k1\*Q.
    ///
    /// This is denoted as Pedersen(P, Q, R) = PoK{ (k0, k1) : R = k0\*P + k1\*Q }.
    ///
    /// Reference [Pedersen](https://doi.org/10.1007/3-540-46766-1_9)
    pub fn pedersen<G: PrimeGroup>(statement: &mut LinearRelation<G>, p: G, q: G, r: G) {
        let [k0_var, k1_var] = statement.allocate_scalars::<2>();
        let [p_var, q_var, r_var] = statement.allocate_elements::<3>();
        statement.append_equation(r_var, k0_var * p_var + k1_var * q_var);
        statement.set_elements([(p_var, p), (q_var, q), (r_var, r)]);
    }

    /// Relation used to prove knowledge of k such that X = k\*P, Y = k\*Q.
    ///
    /// This is denoted as DLEQ(P, Q, X, Y) = PoK{ k : X = k\*P, Y = k\*Q }
    ///
    /// Reference [Chaum-Pedersen](https://doi.org/10.1007/3-540-48071-4_7)
    pub fn dleq<G: PrimeGroup>(statement: &mut LinearRelation<G>, p: G, q: G, x: G, y: G) {
        let k_var = statement.allocate_scalar();
        let [p_var, q_var, x_var, y_var] = statement.allocate_elements::<4>();
        statement.append_equation(x_var, k_var * p_var);
        statement.append_equation(y_var, k_var * q_var);
        statement.set_elements([(p_var, p), (q_var, q), (x_var, x), (y_var, y)]);
    }
}

#[cfg(test)]
mod tests;
