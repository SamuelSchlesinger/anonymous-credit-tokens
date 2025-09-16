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
use rand_core::CryptoRngCore;
use sigma_rs::LinearRelation;
use std::ops::Neg;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::ZeroizeOnDrop;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidIssuanceRequestProof,
    InvalidIssuanceResponseProof,
    DoubleSpendError,
    InvalidRefundProof,
    InvalidRefundResponseProof,
    IdentityPointError,
    InvalidClientSpendProof,
    AmountTooBigError,
    ScalarOutOfRangeError,
}

/// The bit length used for binary decomposition of values in range proofs.
/// This defines the maximum value (2^128 - 1) that can be represented.
pub const L: usize = 128;

mod transcript;
use transcript::Transcript;

pub mod cbor;

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
/// * `Ok(u128)` - The u128 value if the Scalar is within the u128 range
/// * `Err(Error) - If the Scalar value is too large to fit in a u128
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
    /// First generator point used in commitment schemes
    h1: RistrettoBasepointTable,
    /// Second generator point used in commitment schemes
    h2: RistrettoBasepointTable,
    /// Third generator point used in commitment schemes
    h3: RistrettoBasepointTable,
}

impl std::fmt::Debug for Params {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Params")
            .field("h1", &"RistrettoBasepointTable")
            .field("h2", &"RistrettoBasepointTable")
            .field("h3", &"RistrettoBasepointTable")
            .finish()
    }
}

impl PartialEq for Params {
    fn eq(&self, _other: &Self) -> bool {
        // For testing purposes, assume all Params instances are different
        // unless they are the same object. In real usage, Params should
        // be created deterministically with domain separation.
        false
    }
}

impl Eq for Params {}

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
        // Construct the structured domain separator
        let domain_separator = format!(
            "ACT-v1:{}:{}:{}:{}",
            organization, service, deployment_id, version
        );

        // Hash the domain separator with length prefix to create a seed
        let mut hasher = blake3::Hasher::new();
        let domain_separator_bytes = domain_separator.as_bytes();
        hasher.update(&(domain_separator_bytes.len() as u64).to_be_bytes());
        hasher.update(domain_separator_bytes);
        let seed = hasher.finalize();

        // Generate H1, H2, H3 using counter-based approach
        let h1 = Self::hash_to_ristretto(&domain_separator, seed.as_bytes(), 0);
        let h2 = Self::hash_to_ristretto(&domain_separator, seed.as_bytes(), 1);
        let h3 = Self::hash_to_ristretto(&domain_separator, seed.as_bytes(), 2);

        Params {
            h1: RistrettoBasepointTable::create(&h1),
            h2: RistrettoBasepointTable::create(&h2),
            h3: RistrettoBasepointTable::create(&h3),
        }
    }

    /// Hash to Ristretto255 point using BLAKE3 with counter.
    ///
    /// This implements a deterministic hash-to-curve function that maps
    /// the domain separator, seed, and counter to a Ristretto255 point.
    /// All inputs are length-prefixed to ensure domain separation.
    ///
    /// # Arguments
    ///
    /// * `domain_separator` - The domain separator string
    /// * `seed` - The seed bytes (typically from hashing the domain separator)
    /// * `counter` - A counter to generate different points from the same seed
    ///
    /// # Returns
    ///
    /// A deterministically generated Ristretto255 point
    fn hash_to_ristretto(domain_separator: &str, seed: &[u8], counter: u32) -> RistrettoPoint {
        let mut hasher = blake3::Hasher::new();

        // Add domain separator with length prefix
        let domain_separator_bytes = domain_separator.as_bytes();
        hasher.update(&(domain_separator_bytes.len() as u64).to_be_bytes());
        hasher.update(domain_separator_bytes);

        // Add seed with length prefix
        hasher.update(&(seed.len() as u64).to_be_bytes());
        hasher.update(seed);

        // Add counter with length prefix (4 bytes for u32)
        hasher.update(&(4u64).to_be_bytes());
        hasher.update(&counter.to_le_bytes());

        // Generate 64 bytes for from_uniform_bytes
        let mut uniform_bytes = [0u8; 64];
        let mut output_reader = hasher.finalize_xof();
        output_reader.fill(&mut uniform_bytes);

        RistrettoPoint::from_uniform_bytes(&uniform_bytes)
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
/// identity. The token includes a credit value `c` that represents the total amount
/// of credits available to spend.
#[derive(ZeroizeOnDrop, Debug, Clone, PartialEq)]
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
        let prover = statement.into_nizk(b"request").unwrap();
        let witness = vec![self.k, self.r];
        let pok = prover.prove_compact(&witness, &mut rng).unwrap();

        IssuanceRequest { big_k, pok }
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
    /// * `Ok(CreditToken)` - A valid credit token if the issuer's response is verified
    /// * `Err(Error)` - If the verification fails, indicating a potential invalid response
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
    /// # let credit_amount = Scalar::from(20u128);
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
    ) -> Result<CreditToken, Error> {
        // Reconstruct the signature base points for verification
        let g = RistrettoPoint::generator();
        let x_a = g + &params.h1 * &response.c + request.big_k;
        let x_g = g * response.e + public.w;

        // Verify that the challenge matches the expected value
        let mut statement = LinearRelation::new();
        proofs::dleq(&mut statement, response.a, g, x_a, x_g);
        let verifier = statement.into_nizk(b"respond").unwrap();
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
        })
    }
}

/// The issuer's response to a client's issuance request.
///
/// This response contains the cryptographic signature components and proof
/// values that allow the client to construct a valid credit token. It includes
/// the credit amount (`c`) assigned by the issuer and the BBS+ signature
/// elements that authenticate this amount.
#[derive(ZeroizeOnDrop, Debug, Clone, PartialEq)]
pub struct IssuanceResponse {
    /// The BBS+ signature's main component
    a: RistrettoPoint,
    /// A random scalar used in the BBS+ signature
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
    /// * `Ok(IssuanceResponse)` - The response containing the signature if the request is valid
    /// * `Err(Error)` - If the request verification fails
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
    /// let credit_amount = Scalar::from(20u128);
    /// let response = private_key.issue(&params, &request, credit_amount, OsRng).unwrap();
    /// ```
    pub fn issue(
        &self,
        params: &Params,
        request: &IssuanceRequest,
        c: Scalar,
        mut rng: impl CryptoRngCore,
    ) -> Result<IssuanceResponse, Error> {
        // Verify the client's zero-knowledge proof
        let mut statement = LinearRelation::new();
        proofs::pedersen(
            &mut statement,
            params.h2.basepoint(),
            params.h3.basepoint(),
            request.big_k,
        );
        let verifier = statement.into_nizk(b"request").unwrap();
        if verifier.verify_compact(&request.pok).is_err() {
            return Err(Error::InvalidIssuanceRequestProof);
        }

        // Create a BBS+ signature on the client's commitment and credit amount
        let g = RistrettoPoint::generator();
        let e = Scalar::random(&mut rng);
        let exp = e + self.x;
        let x_a = g + &params.h1 * &c + request.big_k;
        let a = x_a * exp.invert();
        let x_g = g * exp;

        // Generate a zero-knowledge proof that the signature is valid
        let mut statement = LinearRelation::new();
        proofs::dleq(&mut statement, a, g, x_a, x_g);
        let prover = statement.into_nizk(b"respond").unwrap();
        let witness = vec![exp];
        let pok = prover.prove_compact(&witness, &mut rng).unwrap();

        Ok(IssuanceResponse { a, e, c, pok })
    }
}

/// A zero-knowledge proof that allows spending credits anonymously.
///
/// This proof demonstrates that the client possesses a valid credit token with
/// sufficient balance to spend the requested amount, without revealing the token itself.
/// The proof includes a nullifier that prevents double-spending, and a range proof
/// that ensures the remaining balance is non-negative.
#[derive(ZeroizeOnDrop, Debug, Clone)]
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
    /// * `Ok(Refund)` - The refund token if the spend proof is valid
    /// * `Err(Error)` - If the spend proof verification fails
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
    /// # let params = Params::new("test-org", "test-service", "test", "2024-01-01");
    /// # let request = pre_issuance.request(&params, OsRng);
    /// # let response = private_key.issue(&params, &request, Scalar::from(20u128), OsRng).unwrap();
    /// # let credit_token = pre_issuance.to_credit_token(&params, private_key.public(), &request, &response).unwrap();
    /// # let spend_amount = Scalar::from(10u128);
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
    ) -> Result<Refund, Error> {
        if spend_proof.a_prime == RistrettoPoint::identity() {
            return Err(Error::IdentityPointError);
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

        let k_prime = spend_proof
            .com
            .iter()
            .enumerate()
            .map(|(i, com)| com * Scalar::from(2u128.pow(i as u32)))
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
            return Err(Error::InvalidClientSpendProof);
        }

        // Issuing a refund
        let e_star = Scalar::random(&mut rng);
        let g = RistrettoPoint::generator();
        let exp = e_star + self.x;
        let x_a_star = g + k_prime;
        let a_star = x_a_star * exp.invert();
        let x_g = g * exp;

        let mut statement = LinearRelation::new();
        proofs::dleq(&mut statement, a_star, g, x_a_star, x_g);
        let prover = statement.into_nizk(b"refund").unwrap();
        let witness = vec![exp];
        let pok = prover.prove_compact(&witness, &mut rng).unwrap();

        Ok(Refund {
            a: a_star,
            e: e_star,
            pok,
        })
    }
}

/// Client state maintained during the refund protocol.
///
/// This structure holds the client's secret values that are needed to complete
/// the refund protocol and construct a new credit token with the remaining balance.
/// The client must keep this information private after spending credits and while
/// awaiting a refund.
#[derive(ZeroizeOnDrop, Debug, Clone)]
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
    result.iter_mut().enumerate().for_each(|(i, result_elem)| {
        let b = i / 8; // Byte index
        let j = i % 8; // Bit position within the byte
        let bit = (bytes[b] >> j) & 0b1; // Extract the bit
        *result_elem = Scalar::from(bit as u128); // Convert to scalar (0 or 1)
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
    /// # let params = Params::new("test-org", "test-service", "test", "2024-01-01");
    /// # let request = pre_issuance.request(&params, OsRng);
    /// # let response = private_key.issue(&params, &request, Scalar::from(20u128), OsRng).unwrap();
    /// # let credit_token = pre_issuance.to_credit_token(&params, private_key.public(), &request, &response).unwrap();
    /// #
    /// // Spend 10 credits (where 10 <= token balance < 2^128)
    /// let spend_amount = Scalar::from(10u128);
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
        let s_i: Vec<Scalar> = (0..L).map(|_| Scalar::random(&mut rng)).collect();
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
        let r_star = s_i
            .iter()
            .enumerate()
            .map(|(i, si)| si * Scalar::from(2u128.pow(i as u32)))
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
#[derive(ZeroizeOnDrop, Debug, Clone, PartialEq)]
pub struct Refund {
    /// The BBS+ signature's main component for the new credit token
    a: RistrettoPoint,
    /// A random scalar used in the BBS+ signature
    e: Scalar,
    /// Proof of knowledge of correct BBS signature.
    pok: Vec<u8>,
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
    /// * `Ok(CreditToken)` - A new credit token with the remaining balance if the refund is valid
    /// * `Err(Error)r - If the verification fails
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
    /// # let params = Params::new("test-org", "test-service", "test", "2024-01-01");
    /// # let request = pre_issuance.request(&params, OsRng);
    /// # let response = private_key.issue(&params, &request, Scalar::from(20u128), OsRng).unwrap();
    /// # let credit_token = pre_issuance.to_credit_token(&params, public_key, &request, &response).unwrap();
    /// # let spend_amount = Scalar::from(10u128);
    /// # let (spend_proof, prerefund) = credit_token.prove_spend(&params, spend_amount, OsRng);
    /// # let refund = private_key.refund(&params, &spend_proof, OsRng).unwrap();
    /// #
    /// // Construct the new credit token with the remaining balance
    /// let new_credit_token = prerefund.to_credit_token(
    ///     &spend_proof,
    ///     &refund,
    ///     public_key
    /// ).unwrap();
    /// ```
    pub fn to_credit_token(
        &self,
        spend_proof: &SpendProof,
        refund: &Refund,
        public_key: &PublicKey,
    ) -> Result<CreditToken, Error> {
        // Verify the client's zero-knowledge proof
        let g = RistrettoPoint::generator();
        let x_a = g + spend_proof
            .com
            .iter()
            .enumerate()
            .map(|(i, com)| com * Scalar::from(2u128.pow(i as u32)))
            .fold(RistrettoPoint::identity(), |a, b| a + b);
        let x_g = g * refund.e + public_key.w;

        let mut statement = LinearRelation::new();
        proofs::dleq(&mut statement, refund.a, g, x_a, x_g);
        let verifier = statement.into_nizk(b"refund").unwrap();
        if verifier.verify_compact(&refund.pok).is_err() {
            return Err(Error::InvalidRefundProof);
        }

        // The client now has a new credit token
        Ok(CreditToken {
            a: refund.a,
            e: refund.e,
            k: self.k,
            r: self.r,
            c: self.m,
        })
    }
}

/// Proofs of knowledge used in this protocol.
mod proofs {
    use group::prime::PrimeGroup;
    use sigma_rs::LinearRelation;

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
