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

use group::ff::Field;
use group::Group;
use subtle::ConditionallySelectable;
use zeroize::ZeroizeOnDrop;

use std::ops::Neg;

use crate::ciphersuite::{Ciphersuite, ErrorCode, ParamsError};
use crate::transcript::Transcript;

pub use rand_core::{self, CryptoRngCore};

// ── Structs ────────────────────────────────────────────────────────────

#[derive(ZeroizeOnDrop, Debug, Clone)]
pub struct PrivateKey<C: Ciphersuite> {
    pub(crate) x: C::Scalar,
    #[zeroize(skip)]
    pub(crate) public: PublicKey<C>,
}

#[derive(Debug, Clone)]
pub struct PublicKey<C: Ciphersuite> {
    pub(crate) w: C::Point,
}

#[derive(Clone)]
pub struct Params<C: Ciphersuite> {
    pub(crate) h1: C::ParamPoint,
    pub(crate) h2: C::ParamPoint,
    pub(crate) h3: C::ParamPoint,
    pub(crate) h4: C::ParamPoint,
    pub(crate) transcript_base: blake3::Hasher,
}

impl<C: Ciphersuite> std::fmt::Debug for Params<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Params")
            .field("h1", &"ParamPoint")
            .field("h2", &"ParamPoint")
            .field("h3", &"ParamPoint")
            .field("h4", &"ParamPoint")
            .finish()
    }
}

#[derive(ZeroizeOnDrop, Debug, Clone)]
pub struct PreIssuance<C: Ciphersuite> {
    pub(crate) r: C::Scalar,
    pub(crate) k: C::Scalar,
}

#[derive(ZeroizeOnDrop, Debug, Clone)]
pub struct IssuanceRequest<C: Ciphersuite> {
    pub(crate) big_k: C::Point,
    pub(crate) gamma: C::Scalar,
    pub(crate) k_bar: C::Scalar,
    pub(crate) r_bar: C::Scalar,
}

#[derive(ZeroizeOnDrop, Debug, Clone)]
pub struct IssuanceResponse<C: Ciphersuite> {
    pub(crate) a: C::Point,
    pub(crate) e: C::Scalar,
    pub(crate) gamma: C::Scalar,
    pub(crate) z: C::Scalar,
    pub(crate) c: C::Scalar,
    pub(crate) ctx: C::Scalar,
}

#[derive(ZeroizeOnDrop, Debug, Clone)]
pub struct CreditToken<C: Ciphersuite> {
    pub(crate) a: C::Point,
    pub(crate) e: C::Scalar,
    pub(crate) k: C::Scalar,
    pub(crate) r: C::Scalar,
    pub(crate) c: C::Scalar,
    pub(crate) ctx: C::Scalar,
}

#[derive(ZeroizeOnDrop, Debug, Clone)]
pub struct SpendProof<C: Ciphersuite, const L: usize> {
    pub(crate) k: C::Scalar,
    pub(crate) ctx: C::Scalar,
    pub(crate) s: C::Scalar,
    pub(crate) a_prime: C::Point,
    pub(crate) b_bar: C::Point,
    pub(crate) com: [C::Point; L],
    pub(crate) gamma: C::Scalar,
    pub(crate) e_bar: C::Scalar,
    pub(crate) r2_bar: C::Scalar,
    pub(crate) r3_bar: C::Scalar,
    pub(crate) c_bar: C::Scalar,
    pub(crate) r_bar: C::Scalar,
    pub(crate) w00: C::Scalar,
    pub(crate) w01: C::Scalar,
    pub(crate) gamma0: [C::Scalar; L],
    pub(crate) z: [[C::Scalar; 2]; L],
    pub(crate) k_bar: C::Scalar,
    pub(crate) s_bar: C::Scalar,
}

#[derive(ZeroizeOnDrop, Debug, Clone)]
pub struct PreRefund<C: Ciphersuite> {
    pub(crate) r: C::Scalar,
    pub(crate) k: C::Scalar,
    pub(crate) m: C::Scalar,
    pub(crate) ctx: C::Scalar,
}

#[derive(ZeroizeOnDrop, Debug, Clone)]
pub struct Refund<C: Ciphersuite> {
    pub(crate) a: C::Point,
    pub(crate) e: C::Scalar,
    pub(crate) gamma: C::Scalar,
    pub(crate) z: C::Scalar,
    pub(crate) t: C::Scalar,
}

// ── Helper functions ───────────────────────────────────────────────────

fn pow2_weighted_sum<C: Ciphersuite>(points: &[C::Point]) -> C::Point {
    let n = points.len();
    debug_assert!(n > 0);
    let mut result = points[n - 1];
    for j in (0..n - 1).rev() {
        result = result.double() + points[j];
    }
    result
}

fn pow2_weighted_scalar_sum<C: Ciphersuite>(scalars: &[C::Scalar]) -> C::Scalar {
    let n = scalars.len();
    debug_assert!(n > 0);
    let mut result = scalars[n - 1];
    for j in (0..n - 1).rev() {
        result = result + result + scalars[j];
    }
    result
}

// ── PrivateKey ─────────────────────────────────────────────────────────

impl<C: Ciphersuite> PrivateKey<C> {
    pub fn random(mut rng: impl CryptoRngCore) -> Self {
        let x = <C::Scalar as Field>::random(&mut rng);
        let public = PublicKey {
            w: C::generator_mul(&x),
        };
        PrivateKey { x, public }
    }

    pub fn public(&self) -> &PublicKey<C> {
        &self.public
    }

    pub fn issue<const L: usize>(
        &self,
        params: &Params<C>,
        request: &IssuanceRequest<C>,
        c: C::Scalar,
        ctx: C::Scalar,
        mut rng: impl CryptoRngCore,
    ) -> Result<IssuanceResponse<C>, ErrorCode> {
        const { assert!(L > 0 && L <= 128, "L must be in 1..=128") };

        // Validate credit amount is within range (0 < c < 2^L)
        if c == <C::Scalar as Field>::ZERO || !C::scalar_fits_in_bits::<L>(&c) {
            return Err(ErrorCode::InvalidAmount);
        }

        // Validate received point is not identity (spec Section 5.2)
        if request.big_k == C::Point::identity() {
            return Err(ErrorCode::InvalidProof);
        }

        // Verify the client's zero-knowledge proof
        let k1 = C::multiscalar_mul(
            &[request.k_bar, request.r_bar, request.gamma.neg()],
            &[C::param_to_point(&params.h2), C::param_to_point(&params.h3), request.big_k],
        );

        // Generate the expected challenge value
        let gamma = Transcript::<C>::with(&params.transcript_base, b"request", |transcript| {
            transcript.add_elements([&request.big_k, &k1].into_iter());
        });

        // Verify that the client's proof is valid
        if gamma != request.gamma {
            return Err(ErrorCode::InvalidProof);
        }

        // Create a BBS+ signature on the client's commitment and credit amount.
        let e = <C::Scalar as Field>::random(&mut rng);
        let x_a = C::generator_mul(&<C::Scalar as Field>::ONE)
            + C::param_mul(&params.h1, &c)
            + C::param_mul(&params.h4, &ctx)
            + request.big_k;
        let a = x_a * C::scalar_invert(&(e + self.x));
        let x_g = C::generator_mul(&e) + self.public.w;

        // Generate a zero-knowledge proof that the signature is valid
        let alpha = <C::Scalar as Field>::random(&mut rng);
        let y_a = a * alpha;
        let y_g = C::generator_mul(&alpha);

        // Generate the challenge for the proof using the Fiat-Shamir transform
        let gamma = Transcript::<C>::with(&params.transcript_base, b"respond", |transcript| {
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

    pub fn refund<const L: usize>(
        &self,
        params: &Params<C>,
        spend_proof: &SpendProof<C, L>,
        t: C::Scalar,
        mut rng: impl CryptoRngCore,
    ) -> Result<Refund<C>, ErrorCode> {
        const { assert!(L > 0 && L <= 128, "L must be in 1..=128") };

        // Validate A' is not identity (spec Section 3.5.2, step 3)
        if spend_proof.a_prime == C::Point::identity() {
            return Err(ErrorCode::InvalidProof);
        }

        // Constant-time: scalar operand is the private key.
        let a_bar = spend_proof.a_prime * self.x;

        let h1_point = C::param_to_point(&params.h1);
        let h3_point = C::param_to_point(&params.h3);

        // Spec Section 3.5.2, steps 6-10.
        let big_h1 = C::generator_mul(&<C::Scalar as Field>::ONE)
            + C::param_mul(&params.h2, &spend_proof.k)
            + C::param_mul(&params.h4, &spend_proof.ctx);
        // Spec step 9: A1 = A'*e_bar + B_bar*r2_bar - A_bar*gamma
        let a1 = C::multiscalar_mul(
            &[spend_proof.e_bar, spend_proof.r2_bar, spend_proof.gamma.neg()],
            &[spend_proof.a_prime, spend_proof.b_bar, a_bar],
        );
        // Spec step 10: A2 = B_bar*r3_bar + H1*c_bar + H3*r_bar - H1'*gamma
        let a2 = C::multiscalar_mul(
            &[spend_proof.r3_bar, spend_proof.gamma.neg(), spend_proof.c_bar, spend_proof.r_bar],
            &[spend_proof.b_bar, big_h1, h1_point, h3_point],
        );

        // Spec steps 15-27: compute C'[j][0] and C'[j][1] for the range proof.
        let com0 = spend_proof.com[0];
        let com0_minus_h1 = com0 - C::param_to_point(&params.h1);
        let gamma01_0 = spend_proof.gamma - spend_proof.gamma0[0];
        let mut big_c_prime = [[C::Point::identity(); 2]; L];
        // Spec step 19: C'[0][0] = H2*w00 + H3*z[0][0] - C[0][0]*gamma0[0]
        big_c_prime[0][0] = C::multiscalar_mul(
            &[spend_proof.w00, spend_proof.z[0][0], spend_proof.gamma0[0].neg()],
            &[C::param_to_point(&params.h2), h3_point, com0],
        );
        // Spec step 20: C'[0][1] = H2*w01 + H3*z[0][1] - C[0][1]*gamma1[0]
        big_c_prime[0][1] = C::multiscalar_mul(
            &[spend_proof.w01, spend_proof.z[0][1], gamma01_0.neg()],
            &[C::param_to_point(&params.h2), h3_point, com0_minus_h1],
        );
        // Spec steps 22-27: range proof for bits j = 1..L-1
        #[allow(clippy::needless_range_loop)]
        for j in 1..L {
            let com_j = spend_proof.com[j];
            let com_j_minus_h1 = com_j - C::param_to_point(&params.h1);
            let gamma01_j = spend_proof.gamma - spend_proof.gamma0[j];
            // Spec step 26: C'[j][0] = H3*z[j][0] - C[j][0]*gamma0[j]
            big_c_prime[j][0] = C::multiscalar_mul(
                &[spend_proof.z[j][0], spend_proof.gamma0[j].neg()],
                &[h3_point, com_j],
            );
            // Spec step 27: C'[j][1] = H3*z[j][1] - C[j][1]*gamma1[j]
            big_c_prime[j][1] = C::multiscalar_mul(
                &[spend_proof.z[j][1], gamma01_j.neg()],
                &[h3_point, com_j_minus_h1],
            );
        }

        let k_prime = pow2_weighted_sum::<C>(&spend_proof.com);
        let com_ = C::param_mul(&params.h1, &spend_proof.s) + k_prime;
        let big_c = C::multiscalar_mul(
            &[spend_proof.c_bar.neg(), spend_proof.k_bar, spend_proof.s_bar, spend_proof.gamma.neg()],
            &[h1_point, C::param_to_point(&params.h2), h3_point, com_],
        );

        let gamma = Transcript::<C>::with(&params.transcript_base, b"spend", |transcript| {
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
        if !C::scalar_fits_in_bits::<L>(&t) {
            return Err(ErrorCode::InvalidAmount);
        }
        if !C::scalar_fits_in_bits::<L>(&spend_proof.s) {
            return Err(ErrorCode::InvalidAmount);
        }
        let t_val = C::scalar_to_u128(&t).ok_or(ErrorCode::InvalidAmount)?;
        let s_val = C::scalar_to_u128(&spend_proof.s).ok_or(ErrorCode::InvalidAmount)?;
        if t_val > s_val {
            return Err(ErrorCode::InvalidAmount);
        }

        let e = <C::Scalar as Field>::random(&mut rng);

        let x_a = C::generator_mul(&<C::Scalar as Field>::ONE)
            + k_prime
            + C::param_mul(&params.h1, &t)
            + C::param_mul(&params.h4, &spend_proof.ctx);
        let a = x_a * C::scalar_invert(&(e + self.x));

        let x_g = C::generator_mul(&e) + self.public.w;
        let alpha = <C::Scalar as Field>::random(&mut rng);
        let y_a = a * alpha;
        let y_g = C::generator_mul(&alpha);

        let refund_gamma = Transcript::<C>::with(&params.transcript_base, b"refund", |transcript| {
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

// ── PublicKey ───────────────────────────────────────────────────────────

// (no additional methods beyond derive)

// ── Params ─────────────────────────────────────────────────────────────

impl<C: Ciphersuite> Params<C> {
    pub fn random(mut rng: impl CryptoRngCore) -> Self {
        Self::from_points(
            C::generator_mul(&<C::Scalar as Field>::random(&mut rng)),
            C::generator_mul(&<C::Scalar as Field>::random(&mut rng)),
            C::generator_mul(&<C::Scalar as Field>::random(&mut rng)),
            C::generator_mul(&<C::Scalar as Field>::random(&mut rng)),
        )
    }

    pub fn new(organization: &str, service: &str, deployment_id: &str, version: &str) -> Result<Self, ParamsError> {
        if organization.contains(':') {
            return Err(ParamsError::InvalidDomainSeparator("organization must not contain ':'"));
        }
        if service.contains(':') {
            return Err(ParamsError::InvalidDomainSeparator("service must not contain ':'"));
        }
        if deployment_id.contains(':') {
            return Err(ParamsError::InvalidDomainSeparator("deployment_id must not contain ':'"));
        }
        if version.contains(':') {
            return Err(ParamsError::InvalidDomainSeparator("version must not contain ':'"));
        }

        let domain_separator = format!(
            "ACT-v1:{}:{}:{}:{}",
            organization, service, deployment_id, version
        );

        let mut hasher = blake3::Hasher::new();
        let domain_separator_bytes = domain_separator.as_bytes();
        hasher.update(&(domain_separator_bytes.len() as u64).to_be_bytes());
        hasher.update(domain_separator_bytes);
        let seed = hasher.finalize();

        let h1 = C::hash_to_point(&domain_separator, seed.as_bytes(), 0);
        let h2 = C::hash_to_point(&domain_separator, seed.as_bytes(), 1);
        let h3 = C::hash_to_point(&domain_separator, seed.as_bytes(), 2);
        let h4 = C::hash_to_point(&domain_separator, seed.as_bytes(), 3);

        Ok(Self::from_points(h1, h2, h3, h4))
    }

    fn from_points(h1: C::Point, h2: C::Point, h3: C::Point, h4: C::Point) -> Self {
        let h1 = C::to_param_point(&h1);
        let h2 = C::to_param_point(&h2);
        let h3 = C::to_param_point(&h3);
        let h4 = C::to_param_point(&h4);
        let transcript_base = Transcript::<C>::base_hasher(&h1, &h2, &h3, &h4);
        Params {
            h1,
            h2,
            h3,
            h4,
            transcript_base,
        }
    }
}

// ── PreIssuance ────────────────────────────────────────────────────────

impl<C: Ciphersuite> PreIssuance<C> {
    pub fn random(mut rng: impl CryptoRngCore) -> Self {
        PreIssuance {
            r: <C::Scalar as Field>::random(&mut rng),
            k: <C::Scalar as Field>::random(&mut rng),
        }
    }

    pub fn request(&self, params: &Params<C>, mut rng: impl CryptoRngCore) -> IssuanceRequest<C> {
        let big_k = C::param_mul(&params.h2, &self.k) + C::param_mul(&params.h3, &self.r);

        let k_prime = <C::Scalar as Field>::random(&mut rng);
        let r_prime = <C::Scalar as Field>::random(&mut rng);
        let k1 = C::param_mul(&params.h2, &k_prime) + C::param_mul(&params.h3, &r_prime);

        let gamma = Transcript::<C>::with(&params.transcript_base, b"request", |transcript| {
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

    pub fn to_credit_token<const L: usize>(
        &self,
        params: &Params<C>,
        public: &PublicKey<C>,
        request: &IssuanceRequest<C>,
        response: &IssuanceResponse<C>,
    ) -> Result<CreditToken<C>, ErrorCode> {
        const { assert!(L > 0 && L <= 128, "L must be in 1..=128") };

        // Validate received point is not identity (spec Section 5.2)
        if response.a == C::Point::identity() {
            return Err(ErrorCode::InvalidProof);
        }

        // Validate credit amount fits in L bits (defense-in-depth)
        if !C::scalar_fits_in_bits::<L>(&response.c) {
            return Err(ErrorCode::InvalidAmount);
        }

        // Reconstruct the signature base points for verification
        let x_a = C::generator_mul(&<C::Scalar as Field>::ONE)
            + C::param_mul(&params.h1, &response.c)
            + C::param_mul(&params.h4, &response.ctx)
            + request.big_k;
        let x_g = C::generator_mul(&response.e) + public.w;

        // Verify the response by checking the BBS+ signature proof.
        // All scalar operands are from the issuer's response (public), so
        // variable-time operations are safe here.
        let y_a = C::multiscalar_mul(
            &[response.z, response.gamma.neg()],
            &[response.a, x_a],
        );
        let y_g = x_g * response.gamma.neg() + C::generator_mul(&response.z);

        // Generate the expected challenge value using the Fiat-Shamir transform
        let gamma = Transcript::<C>::with(&params.transcript_base, b"respond", |transcript| {
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

// ── SpendProof ─────────────────────────────────────────────────────────

impl<C: Ciphersuite, const L: usize> SpendProof<C, L> {
    // Compile-time assertion: evaluated when any method references `_ASSERT`,
    // ensuring `L` is in the valid range without runtime cost.
    const _ASSERT: () = assert!(L > 0 && L <= 128, "L must be in 1..=128");

    #[allow(clippy::let_unit_value)]
    pub fn nullifier(&self) -> C::Scalar {
        let _ = Self::_ASSERT;
        self.k
    }

    pub fn context(&self) -> C::Scalar {
        self.ctx
    }

    pub fn charge(&self) -> C::Scalar {
        self.s
    }
}

// ── CreditToken ────────────────────────────────────────────────────────

impl<C: Ciphersuite> CreditToken<C> {
    pub fn nullifier(&self) -> C::Scalar {
        self.k
    }

    pub fn credits(&self) -> C::Scalar {
        self.c
    }

    pub fn prove_spend<const L: usize>(
        &self,
        params: &Params<C>,
        s: C::Scalar,
        mut rng: impl CryptoRngCore,
    ) -> Result<(SpendProof<C, L>, PreRefund<C>), ErrorCode> {
        const { assert!(L > 0 && L <= 128, "L must be in 1..=128") };

        // Validate spend amount fits in L bits
        if !C::scalar_fits_in_bits::<L>(&s) {
            return Err(ErrorCode::InvalidAmount);
        }
        // Validate token balance fits in L bits (defense-in-depth)
        if !C::scalar_fits_in_bits::<L>(&self.c) {
            return Err(ErrorCode::InvalidAmount);
        }
        // Constant-time check: s <= c iff (c - s) fits in L bits.
        if !C::scalar_fits_in_bits::<L>(&(self.c - s)) {
            return Err(ErrorCode::InvalidAmount);
        }

        let r1 = <C::Scalar as Field>::random(&mut rng);
        let r2 = <C::Scalar as Field>::random(&mut rng);
        let c_prime = <C::Scalar as Field>::random(&mut rng);
        let r_prime = <C::Scalar as Field>::random(&mut rng);
        let e_prime = <C::Scalar as Field>::random(&mut rng);
        let r2_prime = <C::Scalar as Field>::random(&mut rng);
        let r3_prime = <C::Scalar as Field>::random(&mut rng);

        let b = C::generator_mul(&<C::Scalar as Field>::ONE)
            + C::param_mul(&params.h1, &self.c)
            + C::param_mul(&params.h2, &self.k)
            + C::param_mul(&params.h3, &self.r)
            + C::param_mul(&params.h4, &self.ctx);
        let a_prime = self.a * (r1 * r2);
        let b_bar = b * r1;
        let r3 = C::scalar_invert(&r1);
        let a1 = a_prime * e_prime + b_bar * r2_prime;
        let a2 = b_bar * r3_prime
            + C::param_mul(&params.h1, &c_prime)
            + C::param_mul(&params.h3, &r_prime);

        let i = C::bits_of::<L>(self.c - s);

        let k_star = <C::Scalar as Field>::random(&mut rng);
        let mut s_i = [<C::Scalar as Field>::ZERO; L];
        for s_val in s_i.iter_mut() {
            *s_val = <C::Scalar as Field>::random(&mut rng);
        }

        let h1_point = C::param_to_point(&params.h1);

        // Spec steps 26-32: create commitments Com[j] for each bit.
        let mut com = [C::Point::identity(); L];
        let h1_bit_0 = C::Point::conditional_select(
            &C::Point::identity(),
            &h1_point,
            i[0],
        );
        com[0] = h1_bit_0
            + C::param_mul(&params.h2, &k_star)
            + C::param_mul(&params.h3, &s_i[0]);
        for j in 1..L {
            let h1_bit = C::Point::conditional_select(
                &C::Point::identity(),
                &h1_point,
                i[j],
            );
            com[j] = h1_bit + C::param_mul(&params.h3, &s_i[j]);
        }
        let mut big_c_prime = [[C::Point::identity(); 2]; L];

        let k0_prime = <C::Scalar as Field>::random(&mut rng);
        let mut s_i_prime = [<C::Scalar as Field>::ZERO; L];
        for s_prime_val in s_i_prime.iter_mut() {
            *s_prime_val = <C::Scalar as Field>::random(&mut rng);
        }
        let mut gamma_i = [<C::Scalar as Field>::ZERO; L];
        for gamma_val in gamma_i.iter_mut() {
            *gamma_val = <C::Scalar as Field>::random(&mut rng);
        }
        let w0 = <C::Scalar as Field>::random(&mut rng);
        let mut z = [<C::Scalar as Field>::ZERO; L];
        for z_val in z.iter_mut() {
            *z_val = <C::Scalar as Field>::random(&mut rng);
        }

        // Spec steps 38-52: compute C'[0][0] and C'[0][1].
        let h2_k0_h3_s0 = C::param_mul(&params.h2, &k0_prime)
            + C::param_mul(&params.h3, &s_i_prime[0]);
        let h1_gamma0 = C::param_mul(&params.h1, &gamma_i[0]);
        let h1_i0_gamma = C::Point::conditional_select(
            &C::Point::identity(),
            &h1_gamma0,
            i[0],
        );
        let h2_diff0 = C::param_mul(&params.h2, &(w0 - k_star * gamma_i[0]));
        let h3_diff0 = C::param_mul(&params.h3, &(z[0] - s_i[0] * gamma_i[0]));
        let diff0 = h2_diff0 + h3_diff0 - h1_i0_gamma;

        big_c_prime[0][0] = C::Point::conditional_select(
            &diff0,
            &h2_k0_h3_s0,
            !i[0],
        );

        big_c_prime[0][1] = C::Point::conditional_select(
            &h2_k0_h3_s0,
            &(diff0 + h1_gamma0),
            !i[0],
        );

        // Spec steps 53-66: compute C'[j][0] and C'[j][1] for j = 1..L-1.
        for j in 1..L {
            let h3_s_j = C::param_mul(&params.h3, &s_i_prime[j]);
            let h1_gamma = C::param_mul(&params.h1, &gamma_i[j]);
            let h3_diff = C::param_mul(&params.h3, &(z[j] - s_i[j] * gamma_i[j]));

            let h1_i_gamma = C::Point::conditional_select(
                &C::Point::identity(),
                &h1_gamma,
                i[j],
            );
            let diff = h3_diff - h1_i_gamma;

            big_c_prime[j][0] = C::Point::conditional_select(
                &diff,
                &h3_s_j,
                !i[j],
            );
            big_c_prime[j][1] = C::Point::conditional_select(
                &h3_s_j,
                &(diff + h1_gamma),
                !i[j],
            );
        }
        let r_star = pow2_weighted_scalar_sum::<C>(&s_i);
        let k_prime_val = <C::Scalar as Field>::random(&mut rng);
        let s_prime_val = <C::Scalar as Field>::random(&mut rng);
        let c_ = C::param_mul(&params.h1, &c_prime.neg())
            + C::param_mul(&params.h2, &k_prime_val)
            + C::param_mul(&params.h3, &s_prime_val);

        let gamma = Transcript::<C>::with(&params.transcript_base, b"spend", |transcript| {
            transcript.add_scalar(&self.k);
            transcript.add_scalar(&self.ctx);
            transcript.add_elements([&a_prime, &b_bar].into_iter());
            transcript.add_elements([&a1, &a2].into_iter());
            transcript.add_elements(com.iter());
            for c_prime_elem in big_c_prime.iter() {
                transcript.add_elements(c_prime_elem.iter());
            }
            transcript.add_element(&c_);
        });

        let e_bar = gamma.neg() * self.e + e_prime;
        let r2_bar = gamma * r2 + r2_prime;
        let r3_bar = gamma * r3 + r3_prime;
        let c_bar = gamma.neg() * self.c + c_prime;
        let r_bar = gamma.neg() * self.r + r_prime;
        let mut gamma00 = [<C::Scalar as Field>::ZERO; L];
        gamma00[0] = C::Scalar::conditional_select(
            &gamma_i[0],
            &(gamma - gamma_i[0]),
            !i[0],
        );
        let w00 = C::Scalar::conditional_select(
            &w0,
            &(gamma00[0] * k_star + k0_prime),
            !i[0],
        );
        let w01 = C::Scalar::conditional_select(
            &((gamma - gamma00[0]) * k_star + k0_prime),
            &w0,
            !i[0],
        );
        let mut z00 = [[<C::Scalar as Field>::ZERO; 2]; L];
        z00[0][0] = C::Scalar::conditional_select(
            &z[0],
            &(gamma00[0] * s_i[0] + s_i_prime[0]),
            !i[0],
        );
        z00[0][1] = C::Scalar::conditional_select(
            &((gamma - gamma00[0]) * s_i[0] + s_i_prime[0]),
            &z[0],
            !i[0],
        );
        for j in 1..L {
            gamma00[j] = C::Scalar::conditional_select(
                &gamma_i[j],
                &(gamma - gamma_i[j]),
                !i[j],
            );
            z00[j][0] = C::Scalar::conditional_select(
                &z[j],
                &(gamma00[j] * s_i[j] + s_i_prime[j]),
                !i[j],
            );
            z00[j][1] = C::Scalar::conditional_select(
                &((gamma - gamma00[j]) * s_i[j] + s_i_prime[j]),
                &z[j],
                !i[j],
            );
        }
        let k_bar = gamma * k_star + k_prime_val;
        let s_bar = gamma * r_star + s_prime_val;

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

// ── Refund ─────────────────────────────────────────────────────────────

impl<C: Ciphersuite> Refund<C> {
    pub fn partial_return(&self) -> C::Scalar {
        self.t
    }
}

// ── PreRefund ──────────────────────────────────────────────────────────

impl<C: Ciphersuite> PreRefund<C> {
    pub fn to_credit_token<const L: usize>(
        &self,
        params: &Params<C>,
        spend_proof: &SpendProof<C, L>,
        refund: &Refund<C>,
        public_key: &PublicKey<C>,
    ) -> Result<CreditToken<C>, ErrorCode> {
        const { assert!(L > 0 && L <= 128, "L must be in 1..=128") };

        // Validate received point is not identity (spec Section 5.2)
        if refund.a == C::Point::identity() {
            return Err(ErrorCode::InvalidProof);
        }

        let x_a = C::generator_mul(&<C::Scalar as Field>::ONE)
            + pow2_weighted_sum::<C>(&spend_proof.com)
            + C::param_mul(&params.h1, &refund.t)
            + C::param_mul(&params.h4, &self.ctx);

        let x_g = C::generator_mul(&refund.e) + public_key.w;
        // All scalar operands below are public constants, issuer-provided
        // (refund.*), or already revealed in the clear (self.ctx), so
        // variable-time operations are safe.
        let y_a = C::multiscalar_mul(
            &[refund.z, refund.gamma.neg()],
            &[refund.a, x_a],
        );
        let y_g = x_g * refund.gamma.neg() + C::generator_mul(&refund.z);

        let gamma = Transcript::<C>::with(&params.transcript_base, b"refund", |transcript| {
            transcript.add_scalars([&refund.e, &refund.t, &self.ctx].into_iter());
            transcript.add_elements([&refund.a, &x_a, &x_g, &y_a, &y_g].into_iter());
        });

        if gamma != refund.gamma {
            return Err(ErrorCode::InvalidProof);
        }

        // Validate partial return amount fits in L bits (defense-in-depth)
        if !C::scalar_fits_in_bits::<L>(&refund.t) {
            return Err(ErrorCode::InvalidAmount);
        }

        let new_balance = self.m + refund.t;

        // Validate resulting balance fits in L bits (defense-in-depth)
        if !C::scalar_fits_in_bits::<L>(&new_balance) {
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

// ── Conversion helpers ─────────────────────────────────────────────────

pub fn scalar_to_credit<C: Ciphersuite, const L: usize>(
    scalar: &C::Scalar,
) -> Result<u128, ErrorCode> {
    const { assert!(L > 0 && L <= 128, "L must be in 1..=128") };
    if !C::scalar_fits_in_bits::<L>(scalar) {
        return Err(ErrorCode::InvalidAmount);
    }
    C::scalar_to_u128(scalar).ok_or(ErrorCode::InvalidAmount)
}

pub fn credit_to_scalar<C: Ciphersuite, const L: usize>(
    amount: u128,
) -> Result<C::Scalar, ErrorCode> {
    const { assert!(L > 0 && L <= 128, "L must be in 1..=128") };
    if L < 128 && amount >= (1u128 << L) {
        return Err(ErrorCode::InvalidAmount);
    }
    Ok(C::scalar_from_u128(amount))
}
