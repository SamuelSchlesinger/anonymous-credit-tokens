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
//! ## Privacy Considerations
//!
//! - **Request Context (`ctx`)**: The `ctx` value is revealed in the clear during every
//!   spend operation and persists unchanged across the entire issuance-spend-refund chain.
//!   If each issuance uses a distinct `ctx` (e.g., a per-user or per-session identifier),
//!   then every subsequent spend and refund becomes linkable back to that original issuance
//!   and to each other, completely defeating the anonymity guarantees of the scheme. To
//!   preserve unlinkability, assign the same `ctx` to all clients within a given context
//!   (e.g., per-service or per-epoch), or use `Scalar::ZERO` when context binding is not
//!   needed. See the `ctx` parameter on [`PrivateKey::issue`] for more details.
//!
//! - **Nullifier Storage**: The issuer **must** record every nullifier from verified spend
//!   proofs and reject any proof whose nullifier has been seen before. Failure to do so
//!   allows double-spending. Nullifier storage must be persistent and the record-then-refund
//!   sequence must be atomic to prevent race conditions.
//!
//! ## Quick Start
//!
//! ```
//! use anonymous_credit_tokens::{Params, PreIssuance, PrivateKey};
//! use curve25519_dalek::Scalar;
//! use rand_core::OsRng;
//!
//! // Setup: create system parameters and issuer keypair
//! let params = Params::new("example-org", "payment-api", "production", "2024-01-15");
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

use curve25519_dalek::{
    RistrettoPoint, constants::RISTRETTO_BASEPOINT_TABLE, ristretto::RistrettoBasepointTable,
    traits::VartimeMultiscalarMul,
};
use group::Group;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::ZeroizeOnDrop;

use std::ops::Neg;

mod transcript;
use transcript::Transcript;

pub mod cbor;

// Re-export types used in the public API so consumers don't need to depend
// on curve25519-dalek or rand_core directly.
pub use curve25519_dalek::Scalar;
pub use rand_core::{self, CryptoRngCore};

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
            w: RISTRETTO_BASEPOINT_TABLE * &x,
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
    /// Fourth generator point used for request_context binding
    h4: RistrettoBasepointTable,
}

impl std::fmt::Debug for Params {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Params")
            .field("h1", &"RistrettoBasepointTable")
            .field("h2", &"RistrettoBasepointTable")
            .field("h3", &"RistrettoBasepointTable")
            .field("h4", &"RistrettoBasepointTable")
            .finish()
    }
}

impl Params {
    /// Generates random system parameters using the provided random number generator.
    ///
    /// This is primarily intended for testing purposes. In production, use [`Params::new`]
    /// to create deterministic parameters from a domain separator.
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
            h4: RistrettoBasepointTable::create(&RistrettoPoint::random(&mut rng)),
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
        // Validate that no component contains a colon, which would create ambiguous
        // domain separators and could cause different deployments to share parameters.
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

        // Generate H1, H2, H3, H4 using counter-based approach
        let h1 = Self::hash_to_ristretto(&domain_separator, seed.as_bytes(), 0);
        let h2 = Self::hash_to_ristretto(&domain_separator, seed.as_bytes(), 1);
        let h3 = Self::hash_to_ristretto(&domain_separator, seed.as_bytes(), 2);
        let h4 = Self::hash_to_ristretto(&domain_separator, seed.as_bytes(), 3);

        Params {
            h1: RistrettoBasepointTable::create(&h1),
            h2: RistrettoBasepointTable::create(&h2),
            h3: RistrettoBasepointTable::create(&h3),
            h4: RistrettoBasepointTable::create(&h4),
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
#[derive(ZeroizeOnDrop, Debug, Clone)]
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
    /// The request context binding this token to an application-specific context.
    ///
    /// WARNING: This value is revealed in the clear during spending and persists across
    /// refunds. If distinct ctx values are assigned per issuance, the entire token chain
    /// becomes linkable. Use a shared ctx across clients within the same context (e.g.,
    /// per-service or per-epoch) to preserve unlinkability.
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
    /// * `params` - The system parameters for this deployment
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
    /// * `params` - The system parameters for this deployment
    /// * `public` - The issuer's public key
    /// * `request` - The original issuance request sent to the issuer
    /// * `response` - The issuer's response containing the signature components
    ///
    /// # Returns
    ///
    /// * `Ok(CreditToken)` - A valid credit token if the issuer's response is verified
    /// * `Err(ErrorCode::InvalidProof)` - If the verification fails
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
    /// # let response = private_key.issue::<128>(&params, &request, credit_amount, Scalar::ZERO, OsRng).unwrap();
    /// #
    /// let credit_token = pre_issuance.to_credit_token::<128>(
    ///     &params,
    ///     public_key,
    ///     &request,
    ///     &response
    /// ).unwrap();
    /// ```
    pub fn to_credit_token<const L: usize>(
        &self,
        params: &Params,
        public: &PublicKey,
        request: &IssuanceRequest,
        response: &IssuanceResponse,
    ) -> Result<CreditToken, ErrorCode> {
        const { assert!(L > 0 && L <= 128, "L must be in 1..=128") };

        // Validate received point is not identity (spec Section 5.2)
        if response.a == RistrettoPoint::identity() {
            return Err(ErrorCode::InvalidProof);
        }

        // Validate credit amount fits in L bits (defense-in-depth)
        if !scalar_fits_in_bits::<L>(&response.c) {
            return Err(ErrorCode::InvalidAmount);
        }

        // Reconstruct the signature base points for verification
        let x_a = RistrettoPoint::generator()
            + &params.h1 * &response.c
            + &params.h4 * &response.ctx
            + request.big_k;
        let x_g = RISTRETTO_BASEPOINT_TABLE * &response.e + public.w;

        // Verify the response by checking the BBS+ signature proof.
        // All scalar operands are from the issuer's response (public), so
        // variable-time operations are safe here.
        let y_a = RistrettoPoint::vartime_multiscalar_mul(
            [response.z, response.gamma.neg()],
            [response.a, x_a],
        );
        let y_g = RistrettoPoint::vartime_double_scalar_mul_basepoint(
            &response.gamma.neg(),
            &x_g,
            &response.z,
        );

        // Generate the expected challenge value using the Fiat-Shamir transform
        let gamma = Transcript::with(params, b"respond", |transcript| {
            transcript.add_scalars([&response.c, &response.ctx, &response.e].into_iter());
            transcript.add_elements([&response.a, &x_a, &x_g, &y_a, &y_g].into_iter());
        });

        // Verify that the challenge matches the expected value
        if gamma != response.gamma {
            return Err(ErrorCode::InvalidProof);
        }

        // Construct the credit token with the verified signature
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
/// This response contains the cryptographic signature components and proof
/// values that allow the client to construct a valid credit token. It includes
/// the credit amount (`c`) assigned by the issuer and the BBS+ signature
/// elements that authenticate this amount.
#[derive(ZeroizeOnDrop, Debug, Clone)]
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
    /// The request context binding this credential to an application-specific context
    ctx: Scalar,
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
    /// # Type Parameters
    ///
    /// * `L` - The bit-length for credit amount range proofs. Credit values must be
    ///   in the range `[1, 2^L)`. Typical value: `128` for u128-compatible amounts.
    ///   Must be `<= 128`.
    ///
    /// # Arguments
    ///
    /// * `params` - The system parameters for this deployment
    /// * `request` - The client's issuance request
    /// * `c` - The amount of credits to issue (must be in range `(0, 2^L)`)
    /// * `ctx` - The request context binding this credential to an application-specific
    ///   context. This value is revealed in the clear during spending and persists across
    ///   refunds. To preserve unlinkability, use a shared ctx across clients within the
    ///   same context (e.g., per-service or per-epoch), not per-client values.
    /// * `rng` - A cryptographically secure random number generator
    ///
    /// # Returns
    ///
    /// * `Ok(IssuanceResponse)` - The response containing the signature if the request is valid
    /// * `Err(ErrorCode::InvalidProof)` - If the request verification fails
    /// * `Err(ErrorCode::InvalidAmount)` - If `c` is zero or `>= 2^L`
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
    /// let response = private_key.issue::<128>(&params, &request, credit_amount, Scalar::ZERO, OsRng).unwrap();
    /// ```
    pub fn issue<const L: usize>(
        &self,
        params: &Params,
        request: &IssuanceRequest,
        c: Scalar,
        ctx: Scalar,
        mut rng: impl CryptoRngCore,
    ) -> Result<IssuanceResponse, ErrorCode> {
        const { assert!(L > 0 && L <= 128, "L must be in 1..=128") };

        // Validate credit amount is within range (0 < c < 2^L)
        if c == Scalar::ZERO || !scalar_fits_in_bits::<L>(&c) {
            return Err(ErrorCode::InvalidAmount);
        }

        // Validate received point is not identity (spec Section 5.2)
        if request.big_k == RistrettoPoint::identity() {
            return Err(ErrorCode::InvalidProof);
        }

        // Verify the client's zero-knowledge proof
        let k1 = (&params.h2 * &request.k_bar + &params.h3 * &request.r_bar)
            - request.big_k * request.gamma;

        // Generate the expected challenge value
        let gamma = Transcript::with(params, b"request", |transcript| {
            transcript.add_elements([&request.big_k, &k1].into_iter());
        });

        // Verify that the client's proof is valid
        if gamma != request.gamma {
            return Err(ErrorCode::InvalidProof);
        }

        // Create a BBS+ signature on the client's commitment and credit amount
        let e = Scalar::random(&mut rng);
        let x_a = RistrettoPoint::generator() + &params.h1 * &c + &params.h4 * &ctx + request.big_k;
        let a = x_a * (e + self.x).invert();
        let x_g = RISTRETTO_BASEPOINT_TABLE * &e + self.public.w;

        // Generate a zero-knowledge proof that the signature is valid
        let alpha = Scalar::random(&mut rng);
        let y_a = a * alpha;
        let y_g = RISTRETTO_BASEPOINT_TABLE * &alpha;

        // Generate the challenge for the proof using the Fiat-Shamir transform
        let gamma = Transcript::with(params, b"respond", |transcript| {
            transcript.add_scalars([&c, &ctx, &e].into_iter());
            transcript.add_elements([&a, &x_a, &x_g, &y_a, &y_g].into_iter());
        });

        // Calculate the response value for the proof
        let z = gamma * (self.x + e) + alpha;

        Ok(IssuanceResponse {
            a,
            e,
            gamma,
            z,
            c,
            ctx,
        })
    }
}

/// A zero-knowledge proof that allows spending credits anonymously.
///
/// This proof demonstrates that the client possesses a valid credit token with
/// sufficient balance to spend the requested amount, without revealing the token itself.
/// The proof includes a nullifier that prevents double-spending, and a range proof
/// that ensures the remaining balance is non-negative.
#[derive(ZeroizeOnDrop, Debug, Clone)]
pub struct SpendProof<const L: usize> {
    /// The nullifier, uniquely identifying this spend to prevent double-spending
    k: Scalar,
    /// The request context for this spend
    ctx: Scalar,
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

impl<const L: usize> SpendProof<L> {
    const _ASSERT: () = assert!(L > 0 && L <= 128, "L must be in 1..=128");

    /// Returns the nullifier associated with this spend.
    ///
    /// The nullifier is a unique identifier for this spend that should be recorded
    /// by the issuer to prevent double-spending. If the same nullifier is seen twice,
    /// the second spend attempt should be rejected.
    ///
    /// # Returns
    ///
    /// The nullifier as a `Scalar` value
    #[allow(clippy::let_unit_value)]
    pub fn nullifier(&self) -> Scalar {
        let _ = Self::_ASSERT;
        self.k
    }

    /// Returns the request context associated with this spend.
    ///
    /// # Returns
    ///
    /// The request context as a `Scalar` value
    pub fn context(&self) -> Scalar {
        self.ctx
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
    /// The issuer may choose to return `t` credits (where `0 <= t <= s`) back to the
    /// client via the partial credit return mechanism. The resulting token will have
    /// `c - s + t` credits. Use `Scalar::ZERO` for `t` to consume the full spend amount.
    ///
    /// # Security Warning
    ///
    /// This method implements only the proof verification and refund issuance portions
    /// of the spec's `VerifyAndRefund` function. The caller MUST also:
    ///
    /// 1. Check that `spend_proof.nullifier()` has not been previously recorded
    /// 2. Atomically record the nullifier before returning the refund to the client
    /// 3. Ensure the refund remains retrievable if the client's connection drops
    ///
    /// ```rust,no_run
    /// # use anonymous_credit_tokens::*;
    /// # fn example(private_key: &PrivateKey, params: &Params,
    /// #     spend_proof: &SpendProof<128>, nullifier_db: &mut std::collections::HashSet<Scalar>)
    /// #     -> Result<Refund, ErrorCode> {
    /// // Step 1: Check nullifier
    /// let nullifier = spend_proof.nullifier();
    /// if nullifier_db.contains(&nullifier) {
    ///     return Err(ErrorCode::NullifierReuse);
    /// }
    ///
    /// // Step 2: Verify proof and create refund (returning 0 credits)
    /// let refund = private_key.refund(params, spend_proof, Scalar::ZERO, rand_core::OsRng)?;
    ///
    /// // Step 3: Record nullifier (atomically in production)
    /// nullifier_db.insert(nullifier);
    ///
    /// Ok(refund)
    /// # }
    /// ```
    ///
    /// # Arguments
    ///
    /// * `params` - The system parameters for this deployment
    /// * `spend_proof` - The client's proof of valid spending
    /// * `t` - Credits to return to the client (`0 <= t <= s`, must fit in `L` bits)
    /// * `rng` - A cryptographically secure random number generator
    ///
    /// # Returns
    ///
    /// * `Ok(Refund)` - The refund token if the spend proof is valid
    /// * `Err(ErrorCode::InvalidProof)` - If the spend proof verification fails
    /// * `Err(ErrorCode::InvalidAmount)` - If `t > s` or `t` does not fit in `L` bits
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
    /// # let response = private_key.issue::<128>(&params, &request, Scalar::from(20u128), Scalar::ZERO, OsRng).unwrap();
    /// # let credit_token = pre_issuance.to_credit_token::<128>(&params, private_key.public(), &request, &response).unwrap();
    /// # let spend_amount = Scalar::from(10u128);
    /// # let (spend_proof, prerefund) = credit_token.prove_spend::<128>(&params, spend_amount, OsRng).unwrap();
    /// #
    /// // First check if we've seen this nullifier before
    /// let nullifier = spend_proof.nullifier();
    /// // ... check nullifier database
    ///
    /// // Then process the refund, returning 0 credits
    /// let refund = private_key.refund(&params, &spend_proof, Scalar::ZERO, OsRng).unwrap();
    /// ```
    pub fn refund<const L: usize>(
        &self,
        params: &Params,
        spend_proof: &SpendProof<L>,
        t: Scalar,
        mut rng: impl CryptoRngCore,
    ) -> Result<Refund, ErrorCode> {
        const { assert!(L > 0 && L <= 128, "L must be in 1..=128") };

        // Validate A' is not identity (spec Section 3.5.2, step 3)
        if spend_proof.a_prime == RistrettoPoint::identity() {
            return Err(ErrorCode::InvalidProof);
        }

        // Constant-time: scalar operand is the private key.
        let a_bar = spend_proof.a_prime * self.x;

        // All remaining verification uses only public spend_proof / params
        // values as scalar operands, so variable-time operations are safe.
        let big_h1 = RistrettoPoint::generator()
            + &params.h2 * &spend_proof.k
            + &params.h4 * &spend_proof.ctx;
        let a1 = RistrettoPoint::vartime_multiscalar_mul(
            [spend_proof.e_bar, spend_proof.r2_bar, spend_proof.gamma.neg()],
            [spend_proof.a_prime, spend_proof.b_bar, a_bar],
        );
        let a2 = RistrettoPoint::vartime_multiscalar_mul(
            [spend_proof.r3_bar, spend_proof.gamma.neg(), spend_proof.c_bar, spend_proof.r_bar],
            [spend_proof.b_bar, big_h1, params.h1.basepoint(), params.h3.basepoint()],
        );
        let h1_point = params.h1.basepoint();
        let h3_point = params.h3.basepoint();
        let com0 = spend_proof.com[0];
        let com0_minus_h1 = com0 - h1_point;
        let gamma01_0 = spend_proof.gamma - spend_proof.gamma0[0];
        let mut big_c_prime = [[RistrettoPoint::identity(); 2]; L];
        big_c_prime[0][0] = RistrettoPoint::vartime_multiscalar_mul(
            [spend_proof.w00, spend_proof.z[0][0], spend_proof.gamma0[0].neg()],
            [params.h2.basepoint(), h3_point, com0],
        );
        big_c_prime[0][1] = RistrettoPoint::vartime_multiscalar_mul(
            [spend_proof.w01, spend_proof.z[0][1], gamma01_0.neg()],
            [params.h2.basepoint(), h3_point, com0_minus_h1],
        );
        #[allow(clippy::needless_range_loop)] // indexes big_c_prime, com, gamma0, z simultaneously
        for j in 1..L {
            let com_j = spend_proof.com[j];
            let com_j_minus_h1 = com_j - h1_point;
            let gamma01_j = spend_proof.gamma - spend_proof.gamma0[j];
            big_c_prime[j][0] = RistrettoPoint::vartime_multiscalar_mul(
                [spend_proof.z[j][0], spend_proof.gamma0[j].neg()],
                [h3_point, com_j],
            );
            big_c_prime[j][1] = RistrettoPoint::vartime_multiscalar_mul(
                [spend_proof.z[j][1], gamma01_j.neg()],
                [h3_point, com_j_minus_h1],
            );
        }

        let pow2_scalars = powers_of_two::<L>();
        let k_prime = RistrettoPoint::vartime_multiscalar_mul(&pow2_scalars, &spend_proof.com);
        let com_ = &params.h1 * &spend_proof.s + k_prime;
        let big_c = RistrettoPoint::vartime_multiscalar_mul(
            [spend_proof.c_bar.neg(), spend_proof.k_bar, spend_proof.s_bar, spend_proof.gamma.neg()],
            [h1_point, params.h2.basepoint(), h3_point, com_],
        );

        let gamma = Transcript::with(params, b"spend", |transcript| {
            transcript.add_scalar(&spend_proof.k);
            transcript.add_scalar(&spend_proof.ctx);
            transcript.add_elements([&spend_proof.a_prime, &spend_proof.b_bar].into_iter());
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

        let x_a = RistrettoPoint::generator() + k_prime + &params.h1 * &t + &params.h4 * &spend_proof.ctx;
        let a = x_a * (e + self.x).invert();

        let x_g = RISTRETTO_BASEPOINT_TABLE * &e + self.public.w;
        let alpha = Scalar::random(&mut rng);
        let y_a = a * alpha;
        let y_g = RISTRETTO_BASEPOINT_TABLE * &alpha;

        let refund_gamma = Transcript::with(params, b"refund", |transcript| {
            transcript.add_scalars([&e, &t, &spend_proof.ctx].into_iter());
            transcript.add_elements([&a, &x_a, &x_g, &y_a, &y_g].into_iter());
        });

        let z = refund_gamma * (self.x + e) + alpha;

        Ok(Refund {
            a,
            e,
            gamma: refund_gamma,
            z,
            t,
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
    /// The request context carried over from the original token
    ctx: Scalar,
}

/// Returns an array of successive powers of two as Scalars: 1, 2, 4, 8, ...
///
/// This avoids overflow issues with `2u128.pow(i)` when i >= 128 and
/// returns a stack-allocated array instead of requiring a Vec collect.
fn powers_of_two<const L: usize>() -> [Scalar; L] {
    let two = Scalar::from(2u64);
    let mut result = [Scalar::ZERO; L];
    if L > 0 {
        result[0] = Scalar::ONE;
        for i in 1..L {
            result[i] = result[i - 1] * two;
        }
    }
    result
}

/// Checks whether all bits at positions >= L are zero in the scalar (constant-time).
///
/// This validates that a scalar value fits within L bits, i.e., is in the range [0, 2^L).
/// The check is performed in constant time to avoid leaking information about the scalar
/// through timing side channels.
fn scalar_fits_in_bits<const L: usize>(s: &Scalar) -> bool {
    let bytes = s.as_bytes();
    let mut any_high_bit = 0u8;
    for i in L..256 {
        any_high_bit |= (bytes[i / 8] >> (i % 8)) & 1;
    }
    bool::from(any_high_bit.ct_eq(&0))
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
fn bits_of<const L: usize>(s: Scalar) -> [Scalar; L] {
    let bytes = s.as_bytes();
    let mut result = [Scalar::ZERO; L];

    // Extract each bit from the scalar's byte representation
    result.iter_mut().enumerate().for_each(|(i, result_elem)| {
        let bit = (bytes[i / 8] >> (i % 8)) & 1;
        *result_elem = Scalar::conditional_select(&Scalar::ZERO, &Scalar::ONE, Choice::from(bit));
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
    /// # Type Parameters
    ///
    /// * `L` - The bit-length for the range proof. Must match the `L` used during issuance.
    ///   Must be `<= 128`.
    ///
    /// # Arguments
    ///
    /// * `params` - The system parameters for this deployment
    /// * `s` - The amount of credits to spend (zero is allowed for re-anonymization)
    /// * `rng` - A cryptographically secure random number generator
    ///
    /// # Returns
    ///
    /// * `Ok((SpendProof, PreRefund))` - The proof and client state if inputs are valid
    /// * `Err(ErrorCode::InvalidAmount)` - If `s` does not fit in `L` bits or `s > c`
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
    /// # let response = private_key.issue::<128>(&params, &request, Scalar::from(20u128), Scalar::ZERO, OsRng).unwrap();
    /// # let credit_token = pre_issuance.to_credit_token::<128>(&params, private_key.public(), &request, &response).unwrap();
    /// #
    /// // Spend 10 credits (where 10 <= token balance < 2^128)
    /// let spend_amount = Scalar::from(10u128);
    /// let (spend_proof, prerefund) = credit_token.prove_spend::<128>(&params, spend_amount, OsRng).unwrap();
    ///
    /// // Send spend_proof to the issuer and keep prerefund for later
    /// ```
    pub fn prove_spend<const L: usize>(
        &self,
        params: &Params,
        s: Scalar,
        mut rng: impl CryptoRngCore,
    ) -> Result<(SpendProof<L>, PreRefund), ErrorCode> {
        const { assert!(L > 0 && L <= 128, "L must be in 1..=128") };

        // Validate spend amount fits in L bits
        if !scalar_fits_in_bits::<L>(&s) {
            return Err(ErrorCode::InvalidAmount);
        }
        // Validate token balance fits in L bits (defense-in-depth)
        if !scalar_fits_in_bits::<L>(&self.c) {
            return Err(ErrorCode::InvalidAmount);
        }
        // Constant-time check: s <= c iff (c - s) fits in L bits.
        // If s > c in the integers, c - s wraps modulo the group order to a ~252-bit value.
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

        let b = RistrettoPoint::generator()
            + &params.h1 * &self.c
            + &params.h2 * &self.k
            + &params.h3 * &self.r
            + &params.h4 * &self.ctx;
        let a_prime = self.a * (r1 * r2);
        let b_bar = b * r1;
        let r3 = r1.invert();
        let a1 = a_prime * e_prime + b_bar * r2_prime;
        let a2 = b_bar * r3_prime + &params.h1 * &c_prime + &params.h3 * &r_prime;

        let i = bits_of::<L>(self.c - s);

        let k_star = Scalar::random(&mut rng);
        let mut s_i = [Scalar::ZERO; L];
        for s_val in s_i.iter_mut() {
            *s_val = Scalar::random(&mut rng);
        }
        let mut com = [RistrettoPoint::identity(); L];
        let h1_point = params.h1.basepoint();
        // Optimization: i[j] is always 0 or 1 (from bits_of), so h1 * i[j] is
        // either identity or h1. Use conditional_select instead of a full scalar mul.
        let h1_bit_0 = RistrettoPoint::conditional_select(
            &RistrettoPoint::identity(),
            &h1_point,
            i[0].ct_eq(&Scalar::ONE),
        );
        com[0] = h1_bit_0 + &params.h2 * &k_star + &params.h3 * &s_i[0];
        for j in 1..L {
            let h1_bit = RistrettoPoint::conditional_select(
                &RistrettoPoint::identity(),
                &h1_point,
                i[j].ct_eq(&Scalar::ONE),
            );
            com[j] = h1_bit + &params.h3 * &s_i[j];
        }
        let mut big_c = [[RistrettoPoint::identity(); 2]; L];
        let mut big_c_prime = [[RistrettoPoint::identity(); 2]; L];

        big_c[0][0] = com[0];
        big_c[0][1] = com[0] - h1_point;
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

        let h2_w0_h3_z0 = &params.h2 * &w0 + &params.h3 * &z[0];
        let h2_k0_h3_s0 = &params.h2 * &k0_prime + &params.h3 * &s_i_prime[0];

        // Optimization: big_c[0][1] = com[0] - h1, so big_c[0][1] * gamma_i[0] =
        // com[0] * gamma_i[0] - h1 * gamma_i[0]. Compute com[0] * gamma_i[0] once
        // and derive the second product via a cheaper basepoint-table mul.
        let com0_gamma = com[0] * gamma_i[0];
        let h1_gamma0 = &params.h1 * &gamma_i[0];
        big_c_prime[0][0] = RistrettoPoint::conditional_select(
            &(h2_w0_h3_z0 - com0_gamma),
            &h2_k0_h3_s0,
            i[0].ct_eq(&Scalar::ZERO),
        );

        big_c_prime[0][1] = RistrettoPoint::conditional_select(
            &h2_k0_h3_s0,
            &(h2_w0_h3_z0 - com0_gamma + h1_gamma0),
            i[0].ct_eq(&Scalar::ZERO),
        );

        for j in 1..L {
            big_c[j][0] = com[j];
            big_c[j][1] = com[j] - h1_point;

            let h3_z_j = &params.h3 * &z[j];
            let h3_s_j = &params.h3 * &s_i_prime[j];

            // Same optimization as j=0: reuse com[j] * gamma_i[j] for both branches.
            let com_gamma = com[j] * gamma_i[j];
            let h1_gamma = &params.h1 * &gamma_i[j];
            big_c_prime[j][0] = RistrettoPoint::conditional_select(
                &(h3_z_j - com_gamma),
                &h3_s_j,
                i[j].ct_eq(&Scalar::ZERO),
            );
            big_c_prime[j][1] = RistrettoPoint::conditional_select(
                &h3_s_j,
                &(h3_z_j - com_gamma + h1_gamma),
                i[j].ct_eq(&Scalar::ZERO),
            );
        }
        let pow2 = powers_of_two::<L>();
        let r_star = s_i
            .iter()
            .zip(pow2.iter())
            .map(|(si, p)| si * p)
            .fold(Scalar::ZERO, |x, y| x + y);
        let k_prime = Scalar::random(&mut rng);
        let s_prime = Scalar::random(&mut rng);
        let c_ = &params.h1 * &c_prime.neg() + &params.h2 * &k_prime + &params.h3 * &s_prime;

        let gamma = Transcript::with(params, b"spend", |transcript| {
            transcript.add_scalar(&self.k);
            transcript.add_scalar(&self.ctx);
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
            ctx: self.ctx,
        };

        Ok((
            SpendProof {
                k: self.k,
                ctx: self.ctx,
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
        ))
    }
}

/// The issuer's response to a spending proof, used to create a new credit token.
///
/// This response contains the cryptographic signature components needed for the client
/// to construct a new credit token with the remaining balance. It includes a BBS+
/// signature on the remaining balance and proof values that authenticate the response.
#[derive(ZeroizeOnDrop, Debug, Clone)]
pub struct Refund {
    /// The BBS+ signature's main component for the new credit token
    a: RistrettoPoint,
    /// A random scalar used in the BBS+ signature
    e: Scalar,
    /// A challenge value generated as part of the proof protocol
    gamma: Scalar,
    /// A response value for the proof of knowledge of the signature
    z: Scalar,
    /// Credits returned to the client (`0 <= t <= s`).
    t: Scalar,
}

impl Refund {
    /// Returns the partial credit return amount chosen by the issuer.
    ///
    /// When the issuer processes a spend of `s` credits, it may choose to
    /// return `t` credits (where `0 <= t <= s`) back to the client. The
    /// resulting token will have `c - s + t` credits instead of `c - s`.
    pub fn partial_return(&self) -> Scalar {
        self.t
    }
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
    /// * `params` - The system parameters for this deployment
    /// * `spend_proof` - The original spending proof sent to the issuer
    /// * `refund` - The issuer's refund response
    /// * `public_key` - The issuer's public key
    ///
    /// # Returns
    ///
    /// * `Ok(CreditToken)` - A new credit token with the remaining balance if the refund is valid
    /// * `Err(ErrorCode::InvalidProof)` - If the verification fails
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
    /// # let response = private_key.issue::<128>(&params, &request, Scalar::from(20u128), Scalar::ZERO, OsRng).unwrap();
    /// # let credit_token = pre_issuance.to_credit_token::<128>(&params, public_key, &request, &response).unwrap();
    /// # let spend_amount = Scalar::from(10u128);
    /// # let (spend_proof, prerefund) = credit_token.prove_spend::<128>(&params, spend_amount, OsRng).unwrap();
    /// # let refund = private_key.refund(&params, &spend_proof, Scalar::ZERO, OsRng).unwrap();
    /// #
    /// // Construct the new credit token with the remaining balance
    /// let new_credit_token = prerefund.to_credit_token(
    ///     &params,
    ///     &spend_proof,
    ///     &refund,
    ///     public_key
    /// ).unwrap();
    /// ```
    pub fn to_credit_token<const L: usize>(
        &self,
        params: &Params,
        spend_proof: &SpendProof<L>,
        refund: &Refund,
        public_key: &PublicKey,
    ) -> Result<CreditToken, ErrorCode> {
        const { assert!(L > 0 && L <= 128, "L must be in 1..=128") };

        // Validate received point is not identity (spec Section 5.2)
        if refund.a == RistrettoPoint::identity() {
            return Err(ErrorCode::InvalidProof);
        }

        // All scalar operands below are public constants, issuer-provided
        // (refund.*), or already revealed in the clear (self.ctx), so
        // variable-time operations are safe.
        let pow2_scalars = powers_of_two::<L>();
        let x_a = RistrettoPoint::generator()
            + RistrettoPoint::vartime_multiscalar_mul(&pow2_scalars, &spend_proof.com)
            + &params.h1 * &refund.t
            + &params.h4 * &self.ctx;

        let x_g = RISTRETTO_BASEPOINT_TABLE * &refund.e + public_key.w;
        let y_a = RistrettoPoint::vartime_multiscalar_mul(
            [refund.z, refund.gamma.neg()],
            [refund.a, x_a],
        );
        let y_g = RistrettoPoint::vartime_double_scalar_mul_basepoint(
            &refund.gamma.neg(),
            &x_g,
            &refund.z,
        );

        let gamma = Transcript::with(params, b"refund", |transcript| {
            transcript.add_scalars([&refund.e, &refund.t, &self.ctx].into_iter());
            transcript.add_elements([&refund.a, &x_a, &x_g, &y_a, &y_g].into_iter());
        });

        if gamma != refund.gamma {
            return Err(ErrorCode::InvalidProof);
        }

        // Validate partial return amount fits in L bits (defense-in-depth)
        if !scalar_fits_in_bits::<L>(&refund.t) {
            return Err(ErrorCode::InvalidAmount);
        }

        let new_balance = self.m + refund.t;

        // Validate resulting balance fits in L bits (defense-in-depth)
        if !scalar_fits_in_bits::<L>(&new_balance) {
            return Err(ErrorCode::InvalidAmount);
        }

        // The client now has a new credit token
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
/// use anonymous_credit_tokens::{scalar_to_credit, credit_to_scalar};
///
/// let scalar = credit_to_scalar::<128>(100).unwrap();
/// assert_eq!(scalar_to_credit::<128>(&scalar), Ok(100));
///
/// // With a smaller L, large values are rejected
/// let big = credit_to_scalar::<128>(1000).unwrap();
/// assert!(scalar_to_credit::<8>(&big).is_err()); // 1000 >= 2^8
/// ```
pub fn scalar_to_credit<const L: usize>(scalar: &Scalar) -> Result<u128, ErrorCode> {
    const { assert!(L > 0 && L <= 128, "L must be in 1..=128") };
    if !scalar_fits_in_bits::<L>(scalar) {
        return Err(ErrorCode::InvalidAmount);
    }
    scalar_to_u128(scalar).ok_or(ErrorCode::InvalidAmount)
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
/// use anonymous_credit_tokens::credit_to_scalar;
///
/// let scalar = credit_to_scalar::<128>(100).unwrap();
/// let zero = credit_to_scalar::<128>(0).unwrap(); // valid for spend amounts
/// ```
pub fn credit_to_scalar<const L: usize>(amount: u128) -> Result<Scalar, ErrorCode> {
    const { assert!(L > 0 && L <= 128, "L must be in 1..=128") };
    if L < 128 && amount >= (1u128 << L) {
        return Err(ErrorCode::InvalidAmount);
    }
    Ok(Scalar::from(amount))
}

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

#[cfg(test)]
mod tests;
