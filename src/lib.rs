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
//! ## Usage Examples
//!
//! See the README.md file for comprehensive usage examples and integration guidance.

use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::RistrettoBasepointTable};
use group::Group;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::ZeroizeOnDrop;

use std::ops::Neg;

/// The bit length used for binary decomposition of values in range proofs.
/// This defines the maximum value (2^32 - 1) that can be represented.
pub const L: usize = 32;

mod transcript;
use transcript::Transcript;

/// Converts a u32 value to a Scalar.
///
/// This function creates a Scalar representation of the provided u32 value.
/// The conversion is done safely within the bounds of the scalar field.
///
/// # Arguments
///
/// * `value` - The u32 value to convert to a Scalar
///
/// # Returns
///
/// A `Scalar` representing the u32 value
///
/// # Example
///
/// ```
/// use anonymous_credit_tokens::u32_to_scalar;
///
/// let scalar = u32_to_scalar(42);
/// ```
pub fn u32_to_scalar(value: u32) -> Scalar {
    Scalar::from(value)
}

/// Attempts to convert a Scalar to a u32 value.
///
/// This function attempts to extract a u32 value from a Scalar. Since Scalars can
/// represent values much larger than a u32, this function returns None if the
/// Scalar represents a value outside the u32 range.
///
/// # Arguments
///
/// * `scalar` - The Scalar value to convert to a u32
///
/// # Returns
///
/// * `Some(u32)` - The u32 value if the Scalar is within the u32 range
/// * `None` - If the Scalar value is too large to fit in a u32
///
/// # Example
///
/// ```
/// use anonymous_credit_tokens::{u32_to_scalar, scalar_to_u32};
///
/// let scalar = u32_to_scalar(42);
/// assert_eq!(scalar_to_u32(&scalar), Some(42));
/// ```
pub fn scalar_to_u32(scalar: &Scalar) -> Option<u32> {
    // Get the low 64 bits of the scalar
    let bytes = scalar.as_bytes();
    let value = u32::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
    ]);

    // Check if the scalar is within u32 range and the high bits are zero
    if bytes[4..].iter().all(|&b| b == 0) {
        Some(value)
    } else {
        None
    }
}

/// The private key of the issuer, used to issue and refund credit tokens.
///
/// This key should be kept secure, as it allows the owner to create new tokens
/// and process refunds. The private key includes the corresponding public key
/// that can be shared with clients.
#[derive(Serialize, Deserialize, ZeroizeOnDrop, Debug)]
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
    /// # Arguments
    ///
    /// * `rng` - A cryptographically secure random number generator
    ///
    /// # Returns
    ///
    /// A new `PrivateKey` with a randomly generated secret scalar and the corresponding public key
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
    ///
    /// # Returns
    ///
    /// A reference to the `PublicKey`
    pub fn public(&self) -> &PublicKey {
        &self.public
    }
}

/// The public key of the issuer, used to verify credit tokens.
///
/// This key is shared with clients so they can validate tokens and create spending proofs.
/// It contains a Ristretto point that serves as the public component of the issuer's keypair.
#[derive(Serialize, Deserialize, Debug)]
pub struct PublicKey {
    /// The public point derived from the secret scalar in the private key
    w: RistrettoPoint,
}

/// System parameters that define the cryptographic setup for the anonymous credentials scheme.
///
/// These parameters are used in various cryptographic operations throughout the protocol.
/// By default, they are deterministically generated from a fixed seed.
#[derive(Clone)]
pub struct Params {
    /// First generator point used in commitment schemes
    h1: RistrettoBasepointTable,
    /// Second generator point used in commitment schemes
    h2: RistrettoBasepointTable,
    /// Third generator point used in commitment schemes
    h3: RistrettoBasepointTable,
}

impl Params {
    /// Generates random system parameters using the provided random number generator.
    ///
    /// This is used internally to create the default parameters with a deterministic seed.
    ///
    /// # Arguments
    ///
    /// * `rng` - A cryptographically secure random number generator
    ///
    /// # Returns
    ///
    /// A new `Params` instance with randomly generated points
    pub fn random(mut rng: impl CryptoRngCore) -> Self {
        Params {
            h1: RistrettoBasepointTable::create(&RistrettoPoint::random(&mut rng)),
            h2: RistrettoBasepointTable::create(&RistrettoPoint::random(&mut rng)),
            h3: RistrettoBasepointTable::create(&RistrettoPoint::random(&mut rng)),
        }
    }

    /// Creates the system parameters using a deterministic seed.
    ///
    /// This ensures that all parties use the same parameters without requiring
    /// a trusted setup ceremony. The seed, which should be innocuous such that it
    /// would be very difficult to imagine it being selected maliciously, is hashed with BLAKE3 to
    /// create a deterministic random number generator. This seed should be scoped to your
    /// specific deployment of Anonymous Credit Tokens.
    pub fn nothing_up_my_sleeve(non_sneaky_input: &[u8]) -> Self {
        let rng = ChaCha20Rng::from_seed(*blake3::hash(non_sneaky_input).as_bytes());
        Self::random(rng)
    }
}

/// Client state maintained during the issuance protocol.
///
/// This structure holds the client's secret values that are needed to complete
/// the issuance protocol and eventually construct a valid credit token. The client
/// must keep this information private during the issuance process.
#[derive(Serialize, Deserialize, ZeroizeOnDrop, Debug)]
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
#[derive(Serialize, Deserialize, ZeroizeOnDrop, Debug)]
pub struct IssuanceRequest {
    /// A commitment to the client's identifier and blinding factor
    big_k: RistrettoPoint,
    /// A challenge value generated as part of the proof protocol
    gamma: Scalar,
    /// A response value for the identifier commitment
    k_bar: Scalar,
    /// A response value for the blinding factor
    r_bar: Scalar,
}

/// The credit token used to store and spend anonymous credits.
///
/// This token represents the client's anonymous credits. It contains the cryptographic
/// elements needed to prove ownership and spend credits without revealing the client's
/// identity. The token includes a credit value `c` that represents the total amount
/// of credits available to spend.
#[derive(Serialize, Deserialize, ZeroizeOnDrop, Debug)]
pub struct CreditToken {
    /// A Ristretto point representing the BBS+ signature component
    a: RistrettoPoint,
    /// A random scalar used in the BBS+ signature
    e: Scalar,
    /// The token's unique identifier (used to prevent double-spending)
    k: Scalar,
    /// A blinding factor used to protect the token's privacy
    r: Scalar,
    /// The amount of credits available in this token
    c: Scalar,
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
    /// # Arguments
    ///
    /// * `rng` - A cryptographically secure random number generator
    ///
    /// # Returns
    ///
    /// A new `PreIssuance` instance with randomly generated values
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
    /// # Arguments
    ///
    /// * `rng` - A cryptographically secure random number generator
    ///
    /// # Returns
    ///
    /// An `IssuanceRequest` that can be sent to the issuer
    ///
    /// # Example
    ///
    /// ```
    /// use anonymous_credit_tokens::{PreIssuance, Params};
    /// use rand_core::OsRng;
    ///
    /// let pre_issuance = PreIssuance::random(OsRng);
    /// let params = Params::nothing_up_my_sleeve(b"innocence v1");
    /// let request = pre_issuance.request(&params, OsRng);
    /// ```
    pub fn request(&self, params: &Params, mut rng: impl CryptoRngCore) -> IssuanceRequest {
        // Create a commitment to the client's identifier and blinding factor
        let big_k = &params.h2 * &self.k + &params.h3 * &self.r;

        // Generate random values for the zero-knowledge proof
        let k_prime = Scalar::random(&mut rng);
        let r_prime = Scalar::random(&mut rng);
        let k1 = &params.h2 * &k_prime + &params.h3 * &r_prime;

        // Generate the challenge value using the Fiat-Shamir transform
        let gamma = Transcript::with(params, b"request", |transcript| {
            transcript.add_elements([&big_k, &k1].into_iter());
        });

        // Calculate the response values for the zero-knowledge proof
        let k_bar = k_prime + self.k * gamma;
        let r_bar = r_prime + self.r * gamma;

        IssuanceRequest {
            big_k,
            gamma,
            k_bar,
            r_bar,
        }
    }

    /// Constructs a credit token from the issuer's response to an issuance request.
    ///
    /// This method verifies the issuer's response and, if valid, creates a credit token
    /// that the client can use to spend credits. The method validates the cryptographic
    /// proof from the issuer to ensure the response is legitimate.
    ///
    /// # Arguments
    ///
    /// * `public` - The issuer's public key
    /// * `request` - The original issuance request sent to the issuer
    /// * `response` - The issuer's response containing the signature components
    ///
    /// # Returns
    ///
    /// * `Some(CreditToken)` - A valid credit token if the issuer's response is verified
    /// * `None` - If the verification fails, indicating a potential invalid response
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
    /// # let params = Params::nothing_up_my_sleeve(b"innocence v1");
    /// # let request = pre_issuance.request(&params, OsRng);
    /// # let credit_amount = Scalar::from(20u64);
    /// # let response = private_key.issue(&params, &request, credit_amount, OsRng).unwrap();
    /// #
    /// let credit_token = pre_issuance.to_credit_token(
    ///     &params,
    ///     public_key,
    ///     &request,
    ///     &response
    /// ).unwrap();
    /// ```
    pub fn to_credit_token(
        &self,
        params: &Params,
        public: &PublicKey,
        request: &IssuanceRequest,
        response: &IssuanceResponse,
    ) -> Option<CreditToken> {
        // Reconstruct the signature base points for verification
        let x_a = RistrettoPoint::generator() + &params.h1 * &response.c + request.big_k;
        let x_g = RistrettoPoint::generator() * response.e + public.w;

        // Verify the response by checking the BBS+ signature proof
        let y_a = response.a * response.z + x_a * response.gamma.neg();
        let y_g = RistrettoPoint::generator() * response.z + x_g * response.gamma.neg();

        // Generate the expected challenge value using the Fiat-Shamir transform
        let gamma = Transcript::with(params, b"respond", |transcript| {
            transcript.add_scalar(&response.e);
            transcript.add_elements([&response.a, &x_a, &x_g, &y_a, &y_g].into_iter());
        });

        // Verify that the challenge matches the expected value
        if gamma != response.gamma {
            return None;
        }

        // Construct the credit token with the verified signature
        Some(CreditToken {
            a: response.a,
            e: response.e,
            r: self.r,
            k: self.k,
            c: response.c,
        })
    }
}

/// The issuer's response to a client's issuance request.
///
/// This response contains the cryptographic signature components and proof
/// values that allow the client to construct a valid credit token. It includes
/// the credit amount (`c`) assigned by the issuer and the BBS+ signature
/// elements that authenticate this amount.
#[derive(Serialize, Deserialize, ZeroizeOnDrop, Debug)]
pub struct IssuanceResponse {
    /// The BBS+ signature's main component
    a: RistrettoPoint,
    /// A random scalar used in the BBS+ signature
    e: Scalar,
    /// A challenge value generated as part of the proof protocol
    gamma: Scalar,
    /// A response value for the proof of knowledge of the signature
    z: Scalar,
    /// The amount of credits being issued
    c: Scalar,
}

impl PrivateKey {
    /// Issues credits to a client in response to their issuance request.
    ///
    /// This method verifies the client's request for legitimacy and, if valid, creates
    /// a cryptographic signature binding the specified credit amount to the client's
    /// commitment. The response contains a BBS+ signature and a zero-knowledge proof
    /// that allows the client to verify the signature's authenticity without revealing
    /// the issuer's private key.
    ///
    /// # Arguments
    ///
    /// * `request` - The client's issuance request
    /// * `c` - The amount of credits to issue
    /// * `rng` - A cryptographically secure random number generator
    ///
    /// # Returns
    ///
    /// * `Some(IssuanceResponse)` - The response containing the signature if the request is valid
    /// * `None` - If the request verification fails
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
    /// # let params = Params::nothing_up_my_sleeve(b"innocence v1");
    /// # let request = pre_issuance.request(&params, OsRng);
    /// #
    /// // Issue 20 credits to the client
    /// let credit_amount = Scalar::from(20u64);
    /// let response = private_key.issue(&params, &request, credit_amount, OsRng).unwrap();
    /// ```
    pub fn issue(
        &self,
        params: &Params,
        request: &IssuanceRequest,
        c: Scalar,
        mut rng: impl CryptoRngCore,
    ) -> Option<IssuanceResponse> {
        // Verify the client's zero-knowledge proof
        let k1 = (&params.h2 * &request.k_bar + &params.h3 * &request.r_bar)
            - request.big_k * request.gamma;

        // Generate the expected challenge value
        let gamma = Transcript::with(params, b"request", |transcript| {
            transcript.add_elements([&request.big_k, &k1].into_iter());
        });

        // Verify that the client's proof is valid
        if gamma != request.gamma {
            return None;
        }

        // Create a BBS+ signature on the client's commitment and credit amount
        let e = Scalar::random(&mut rng);
        let x_a = RistrettoPoint::generator() + &params.h1 * &c + request.big_k;
        let a = x_a * (e + self.x).invert();
        let x_g = RistrettoPoint::generator() * e + self.public.w;

        // Generate a zero-knowledge proof that the signature is valid
        let alpha = Scalar::random(&mut rng);
        let y_a = a * alpha;
        let y_g = RistrettoPoint::generator() * alpha;

        // Generate the challenge for the proof using the Fiat-Shamir transform
        let gamma = Transcript::with(params, b"respond", |transcript| {
            transcript.add_scalar(&e);
            transcript.add_elements([&a, &x_a, &x_g, &y_a, &y_g].into_iter());
        });

        // Calculate the response value for the proof
        let z = gamma * (self.x + e) + alpha;

        Some(IssuanceResponse { a, e, gamma, z, c })
    }
}

/// A zero-knowledge proof that allows spending credits anonymously.
///
/// This proof demonstrates that the client possesses a valid credit token with
/// sufficient balance to spend the requested amount, without revealing the token itself.
/// The proof includes a nullifier that prevents double-spending, and a range proof
/// that ensures the remaining balance is non-negative.
#[derive(Serialize, Deserialize, ZeroizeOnDrop, Debug)]
pub struct SpendProof {
    /// The nullifier, uniquely identifying this spend to prevent double-spending
    k: Scalar,
    /// The amount being spent in this transaction
    s: Scalar,
    /// The blinded signature component
    a_prime: RistrettoPoint,
    /// A blinded token component
    b_bar: RistrettoPoint,
    /// Commitments for the binary decomposition of the remaining balance
    com: [RistrettoPoint; L],
    /// The challenge value for the zero-knowledge proof
    gamma: Scalar,
    /// Response value for the signature proof
    e_bar: Scalar,
    /// Response value for signature transformations
    r2_bar: Scalar,
    /// Response value for signature transformations
    r3_bar: Scalar,
    /// Response value for the credit amount
    c_bar: Scalar,
    /// Response value for the blinding factor
    r_bar: Scalar,
    /// Response value for the range proof (bit 0, value 0)
    w00: Scalar,
    /// Response value for the range proof (bit 0, value 1)
    w01: Scalar,
    /// Challenge values for each bit in the range proof
    gamma0: [Scalar; L],
    /// Response values for the range proof bit commitments
    z: [[Scalar; 2]; L],
    /// Response value for the credit identifier
    k_bar: Scalar,
    /// Response value for the range proof sum commitment
    s_bar: Scalar,
}

impl SpendProof {
    /// Returns the nullifier associated with this spend.
    ///
    /// The nullifier is a unique identifier for this spend that should be recorded
    /// by the issuer to prevent double-spending. If the same nullifier is seen twice,
    /// the second spend attempt should be rejected.
    ///
    /// # Returns
    ///
    /// The nullifier as a `Scalar` value
    pub fn nullifier(&self) -> Scalar {
        self.k
    }

    /// Returns the amount of credits being spent in this transaction.
    ///
    /// # Returns
    ///
    /// The credit amount as a `Scalar` value
    pub fn charge(&self) -> Scalar {
        self.s
    }
}

impl PrivateKey {
    /// Processes a spend proof and issues a refund token for the remaining credits.
    ///
    /// This method verifies the validity of a spend proof and, if valid, issues a refund
    /// token for the remaining balance. The refund token can be used by the client to
    /// construct a new credit token with the remaining balance.
    ///
    /// # Security Warning
    ///
    /// This method does NOT verify that the nullifier has not been seen before. The caller
    /// MUST check that the nullifier returned by `spend_proof.nullifier()` has not been
    /// previously processed to prevent double-spending.
    ///
    /// # Arguments
    ///
    /// * `spend_proof` - The client's proof of valid spending
    /// * `rng` - A cryptographically secure random number generator
    ///
    /// # Returns
    ///
    /// * `Some(Refund)` - The refund token if the spend proof is valid
    /// * `None` - If the spend proof verification fails
    ///
    /// # Example
    ///
    /// ```
    /// # use anonymous_credit_tokens::{PrivateKey, PreIssuance, Params};
    /// # use curve25519_dalek::Scalar;
    /// # use rand_core::OsRng;
    /// #
    /// # // Setup (normally these would come from previous steps)
    /// # let private_key = PrivateKey::random(OsRng);
    /// # let pre_issuance = PreIssuance::random(OsRng);
    /// # let params = Params::nothing_up_my_sleeve(b"innocence v1");
    /// # let request = pre_issuance.request(&params, OsRng);
    /// # let response = private_key.issue(&params, &request, Scalar::from(20u64), OsRng).unwrap();
    /// # let credit_token = pre_issuance.to_credit_token(&params, private_key.public(), &request, &response).unwrap();
    /// # let spend_amount = Scalar::from(10u64);
    /// # let (spend_proof, prerefund) = credit_token.prove_spend(&params, spend_amount, OsRng);
    /// #
    /// // First check if we've seen this nullifier before
    /// let nullifier = spend_proof.nullifier();
    /// // ... check nullifier database
    ///
    /// // Then process the refund
    /// let refund = private_key.refund(&params, &spend_proof, OsRng).unwrap();
    /// ```
    pub fn refund(
        &self,
        params: &Params,
        spend_proof: &SpendProof,
        mut rng: impl CryptoRngCore,
    ) -> Option<Refund> {
        if spend_proof.a_prime == RistrettoPoint::generator() {
            return None;
        }

        let a_bar = spend_proof.a_prime * self.x;
        let big_h1 = RistrettoPoint::generator() + &params.h2 * &spend_proof.k;
        let a1 = spend_proof.a_prime * spend_proof.e_bar
            + spend_proof.b_bar * spend_proof.r2_bar
            + a_bar * spend_proof.gamma.neg();
        let a2 = spend_proof.b_bar * spend_proof.r3_bar
            + &params.h1 * &spend_proof.c_bar
            + &params.h3 * &spend_proof.r_bar
            + big_h1 * spend_proof.gamma.neg();
        let mut gamma01 = [Scalar::ZERO; L];
        gamma01[0] = spend_proof.gamma - spend_proof.gamma0[0];
        let mut big_c = [[RistrettoPoint::identity(); 2]; L];
        big_c[0][0] = spend_proof.com[0];
        big_c[0][1] = spend_proof.com[0] - params.h1.basepoint();
        let mut big_c_prime = [[RistrettoPoint::identity(); 2]; L];
        big_c_prime[0][0] = &params.h2 * &spend_proof.w00 + &params.h3 * &spend_proof.z[0][0]
            - big_c[0][0] * spend_proof.gamma0[0];
        big_c_prime[0][1] = &params.h2 * &spend_proof.w01 + &params.h3 * &spend_proof.z[0][1]
            - big_c[0][1] * gamma01[0];
        for j in 1..L {
            gamma01[j] = spend_proof.gamma - spend_proof.gamma0[j];
            big_c[j][0] = spend_proof.com[j];
            big_c[j][1] = spend_proof.com[j] - params.h1.basepoint();
            big_c_prime[j][0] =
                &params.h3 * &spend_proof.z[j][0] - big_c[j][0] * spend_proof.gamma0[j];
            big_c_prime[j][1] = &params.h3 * &spend_proof.z[j][1] - big_c[j][1] * gamma01[j];
        }

        let k_prime = (0..L)
            .map(|i| spend_proof.com[i] * Scalar::from(2u64.pow(i as u32)))
            .fold(RistrettoPoint::identity(), |a, b| a + b);
        let com_ = &params.h1 * &spend_proof.s + k_prime;
        let big_c = &params.h1 * &spend_proof.c_bar.neg()
            + &params.h2 * &spend_proof.k_bar
            + &params.h3 * &spend_proof.s_bar
            - com_ * spend_proof.gamma;

        let gamma = Transcript::with(params, b"spend", |transcript| {
            transcript.add_scalar(&spend_proof.k);
            transcript.add_elements([&spend_proof.a_prime, &spend_proof.b_bar].into_iter());
            transcript.add_elements([&a1, &a2].into_iter());
            transcript.add_elements(spend_proof.com.iter());
            for c_prime in big_c_prime.iter() {
                transcript.add_elements(c_prime.iter());
            }
            transcript.add_element(&big_c);
        });

        if gamma != spend_proof.gamma {
            return None;
        }

        let e = Scalar::random(&mut rng);

        let x_a = RistrettoPoint::generator() + k_prime;
        let a = x_a * (e + self.x).invert();

        let x_g = RistrettoPoint::generator() * e + self.public.w;
        let alpha = Scalar::random(&mut rng);
        let y_a = a * alpha;
        let y_g = RistrettoPoint::generator() * alpha;

        let refund_gamma = Transcript::with(params, b"refund", |transcript| {
            transcript.add_scalar(&e);
            transcript.add_elements([&a, &x_a, &x_g, &y_a, &y_g].into_iter());
        });

        let z = refund_gamma * (self.x + e) + alpha;

        Some(Refund {
            a,
            e,
            gamma: refund_gamma,
            z,
        })
    }
}

/// Client state maintained during the refund protocol.
///
/// This structure holds the client's secret values that are needed to complete
/// the refund protocol and construct a new credit token with the remaining balance.
/// The client must keep this information private after spending credits and while
/// awaiting a refund.
#[derive(Serialize, Deserialize, ZeroizeOnDrop, Debug)]
pub struct PreRefund {
    /// A random blinding factor for the new credit token
    r: Scalar,
    /// A random identifier for the new credit token
    k: Scalar,
    /// The remaining balance after spending
    m: Scalar,
}

/// Decomposes a scalar value into its binary representation.
///
/// This helper function converts a scalar value into an array of L scalars,
/// where each scalar is either 0 or 1, representing the binary decomposition
/// of the input value. This is used in range proofs to demonstrate that a value
/// falls within a certain range.
///
/// # Arguments
///
/// * `s` - The scalar value to decompose
///
/// # Returns
///
/// An array of L scalars (0 or 1) representing the binary bits of the input
fn bits_of(s: Scalar) -> [Scalar; L] {
    let bytes = s.as_bytes();
    let mut result = [Scalar::ZERO; L];

    // Extract each bit from the scalar's byte representation
    for (i, result_elem) in result.iter_mut().enumerate() {
        let b = i / 8; // Byte index
        let j = i % 8; // Bit position within the byte
        let bit = (bytes[b] >> j) & 0b1; // Extract the bit
        *result_elem = Scalar::from(bit as u64); // Convert to scalar (0 or 1)
    }

    result
}

impl CreditToken {
    /// Returns the number of credits contained within this token.
    pub fn credits(&self) -> Scalar {
        self.c
    }

    /// Creates a zero-knowledge proof for spending credits from this token.
    ///
    /// This method generates a proof that the client possesses a valid credit token with
    /// sufficient balance to spend the requested amount, without revealing the token itself.
    /// The proof includes a range proof to demonstrate that the remaining balance is
    /// non-negative, and a nullifier to prevent double-spending.
    ///
    /// # Precondition
    ///
    /// This function requires that `2^L > self.c >= s`. If this condition is not met,
    /// the proof will be invalid and will be rejected by the issuer.
    ///
    /// # Arguments
    ///
    /// * `s` - The amount of credits to spend
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
    /// # let params = Params::nothing_up_my_sleeve(b"innocence v1");
    /// # let request = pre_issuance.request(&params, OsRng);
    /// # let response = private_key.issue(&params, &request, Scalar::from(20u64), OsRng).unwrap();
    /// # let credit_token = pre_issuance.to_credit_token(&params, private_key.public(), &request, &response).unwrap();
    /// #
    /// // Spend 10 credits (where 10 <= token balance < 2^32)
    /// let spend_amount = Scalar::from(10u64);
    /// let (spend_proof, prerefund) = credit_token.prove_spend(&params, spend_amount, OsRng);
    ///
    /// // Send spend_proof to the issuer and keep prerefund for later
    /// ```
    pub fn prove_spend(
        &self,
        params: &Params,
        s: Scalar,
        mut rng: impl CryptoRngCore,
    ) -> (SpendProof, PreRefund) {
        let r1 = Scalar::random(&mut rng);
        let r2 = Scalar::random(&mut rng);
        let c_prime = Scalar::random(&mut rng);
        let r_prime = Scalar::random(&mut rng);
        let e_prime = Scalar::random(&mut rng);
        let r2_prime = Scalar::random(&mut rng);
        let r3_prime = Scalar::random(&mut rng);

        let b = RistrettoPoint::generator()
            + &params.h1 * &self.c
            + &params.h2 * &self.k
            + &params.h3 * &self.r;
        let a_prime = self.a * (r1 * r2);
        let b_bar = b * r1;
        let r3 = r1.invert();
        let a1 = a_prime * e_prime + b_bar * r2_prime;
        let a2 = b_bar * r3_prime + &params.h1 * &c_prime + &params.h3 * &r_prime;

        let i = bits_of(self.c - s);

        let k_star = Scalar::random(&mut rng);
        let mut s_i = Vec::with_capacity(L);
        for _ in 0..L {
            s_i.push(Scalar::random(&mut rng));
        }
        let mut com = [RistrettoPoint::identity(); L];
        com[0] = &params.h1 * &i[0] + &params.h2 * &k_star + &params.h3 * &s_i[0];
        for j in 1..L {
            com[j] = &params.h1 * &i[j] + &params.h3 * &s_i[j];
        }
        let mut big_c = [[RistrettoPoint::identity(); 2]; L];
        let mut big_c_prime = [[RistrettoPoint::identity(); 2]; L];

        big_c[0][0] = com[0];
        big_c[0][1] = com[0] - params.h1.basepoint();
        let k0_prime = Scalar::random(&mut rng);
        let mut s_i_prime = [Scalar::ZERO; L];
        for s_prime in s_i_prime.iter_mut() {
            *s_prime = Scalar::random(&mut rng);
        }
        let mut gamma_i = [Scalar::ZERO; L];
        for gamma in gamma_i.iter_mut() {
            *gamma = Scalar::random(&mut rng);
        }
        let w0 = Scalar::random(&mut rng);
        let mut z = [Scalar::ZERO; L];
        for z_val in z.iter_mut() {
            *z_val = Scalar::random(&mut rng);
        }

        big_c_prime[0][0] = RistrettoPoint::conditional_select(
            &(&params.h2 * &w0 + &params.h3 * &z[0] - big_c[0][0] * gamma_i[0]),
            &(&params.h2 * &k0_prime + &params.h3 * &s_i_prime[0]),
            i[0].ct_eq(&Scalar::ZERO),
        );

        big_c_prime[0][1] = RistrettoPoint::conditional_select(
            &(&params.h2 * &k0_prime + &params.h3 * &s_i_prime[0]),
            &(&params.h2 * &w0 + &params.h3 * &z[0] - big_c[0][1] * gamma_i[0]),
            i[0].ct_eq(&Scalar::ZERO),
        );

        for j in 1..L {
            big_c[j][0] = com[j];
            big_c[j][1] = com[j] - params.h1.basepoint();

            big_c_prime[j][0] = RistrettoPoint::conditional_select(
                &(&params.h3 * &z[j] - big_c[j][0] * gamma_i[j]),
                &(&params.h3 * &s_i_prime[j]),
                i[j].ct_eq(&Scalar::ZERO),
            );
            big_c_prime[j][1] = RistrettoPoint::conditional_select(
                &(&params.h3 * &s_i_prime[j]),
                &(&params.h3 * &z[j] - big_c[j][1] * gamma_i[j]),
                i[j].ct_eq(&Scalar::ZERO),
            );
        }
        let r_star = (0..L)
            .map(|i| s_i[i] * Scalar::from(2u64.pow(i as u32)))
            .fold(Scalar::ZERO, |x, y| x + y);
        let k_prime = Scalar::random(&mut rng);
        let s_prime = Scalar::random(&mut rng);
        let c_ = &params.h1 * &c_prime.neg() + &params.h2 * &k_prime + &params.h3 * &s_prime;

        let gamma = Transcript::with(params, b"spend", |transcript| {
            transcript.add_scalar(&self.k);
            transcript.add_elements([&a_prime, &b_bar].into_iter());
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
        let mut gamma00 = [Scalar::ZERO; L];
        gamma00[0] = Scalar::conditional_select(
            &gamma_i[0],
            &(gamma - gamma_i[0]),
            i[0].ct_eq(&Scalar::ZERO),
        );
        let w00 = Scalar::conditional_select(
            &w0,
            &(gamma00[0] * k_star + k0_prime),
            i[0].ct_eq(&Scalar::ZERO),
        );
        let w01 = Scalar::conditional_select(
            &((gamma - gamma00[0]) * k_star + k0_prime),
            &w0,
            i[0].ct_eq(&Scalar::ZERO),
        );
        let mut z00 = [[Scalar::ZERO; 2]; L];
        z00[0][0] = Scalar::conditional_select(
            &z[0],
            &(gamma00[0] * s_i[0] + s_i_prime[0]),
            i[0].ct_eq(&Scalar::ZERO),
        );
        z00[0][1] = Scalar::conditional_select(
            &((gamma - gamma00[0]) * s_i[0] + s_i_prime[0]),
            &z[0],
            i[0].ct_eq(&Scalar::ZERO),
        );
        for j in 1..L {
            gamma00[j] = Scalar::conditional_select(
                &gamma_i[j],
                &(gamma - gamma_i[j]),
                i[j].ct_eq(&Scalar::ZERO),
            );
            z00[j][0] = Scalar::conditional_select(
                &z[j],
                &(gamma00[j] * s_i[j] + s_i_prime[j]),
                i[j].ct_eq(&Scalar::ZERO),
            );
            z00[j][1] = Scalar::conditional_select(
                &((gamma - gamma00[j]) * s_i[j] + s_i_prime[j]),
                &z[j],
                i[j].ct_eq(&Scalar::ZERO),
            );
        }
        let k_bar = gamma * k_star + k_prime;
        let s_bar = gamma * r_star + s_prime;

        let prerefund = PreRefund {
            k: k_star,
            r: r_star,
            m: self.c - s,
        };

        (
            SpendProof {
                k: self.k,
                s,
                a_prime,
                b_bar,
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
        )
    }
}

/// The issuer's response to a spending proof, used to create a new credit token.
///
/// This response contains the cryptographic signature components needed for the client
/// to construct a new credit token with the remaining balance. It includes a BBS+
/// signature on the remaining balance and proof values that authenticate the response.
#[derive(Serialize, Deserialize, ZeroizeOnDrop, Debug)]
pub struct Refund {
    /// The BBS+ signature's main component for the new credit token
    a: RistrettoPoint,
    /// A random scalar used in the BBS+ signature
    e: Scalar,
    /// A challenge value generated as part of the proof protocol
    gamma: Scalar,
    /// A response value for the proof of knowledge of the signature
    z: Scalar,
}

impl PreRefund {
    /// Constructs a new credit token from the refund response.
    ///
    /// This method verifies the issuer's refund response and, if valid, creates a new
    /// credit token with the remaining balance. This completes the spending protocol
    /// by providing the client with a new token for their unspent credits.
    ///
    /// # Arguments
    ///
    /// * `spend_proof` - The original spending proof sent to the issuer
    /// * `refund` - The issuer's refund response
    /// * `public_key` - The issuer's public key
    ///
    /// # Returns
    ///
    /// * `Some(CreditToken)` - A new credit token with the remaining balance if the refund is valid
    /// * `None` - If the verification fails
    ///
    /// # Example
    ///
    /// ```
    /// # use anonymous_credit_tokens::{PrivateKey, PreIssuance, Params};
    /// # use curve25519_dalek::Scalar;
    /// # use rand_core::OsRng;
    /// #
    /// # // Setup (normally these would come from previous steps)
    /// # let private_key = PrivateKey::random(OsRng);
    /// # let public_key = private_key.public();
    /// # let pre_issuance = PreIssuance::random(OsRng);
    /// # let params = Params::nothing_up_my_sleeve(b"innocence v1");
    /// # let request = pre_issuance.request(&params, OsRng);
    /// # let response = private_key.issue(&params, &request, Scalar::from(20u64), OsRng).unwrap();
    /// # let credit_token = pre_issuance.to_credit_token(&params, public_key, &request, &response).unwrap();
    /// # let spend_amount = Scalar::from(10u64);
    /// # let (spend_proof, prerefund) = credit_token.prove_spend(&params, spend_amount, OsRng);
    /// # let refund = private_key.refund(&params, &spend_proof, OsRng).unwrap();
    /// #
    /// // Construct the new credit token with the remaining balance
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
    ) -> Option<CreditToken> {
        let x_a = RistrettoPoint::generator()
            + (0..L)
                .map(|i| spend_proof.com[i] * Scalar::from(2u64.pow(i as u32)))
                .fold(RistrettoPoint::identity(), |a, b| a + b);

        let x_g = RistrettoPoint::generator() * refund.e + public_key.w;
        let y_a = refund.a * refund.z + x_a * refund.gamma.neg();
        let y_g = RistrettoPoint::generator() * refund.z + x_g * refund.gamma.neg();

        let gamma = Transcript::with(params, b"refund", |transcript| {
            transcript.add_scalar(&refund.e);
            transcript.add_elements([&refund.a, &x_a, &x_g, &y_a, &y_g].into_iter());
        });

        if gamma != refund.gamma {
            return None;
        }

        // The client now has a new credit token
        Some(CreditToken {
            a: refund.a,
            e: refund.e,
            k: self.k,
            r: self.r,
            c: self.m,
        })
    }
}

#[cfg(test)]
mod tests;
