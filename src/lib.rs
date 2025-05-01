use curve25519_dalek::{RistrettoPoint, Scalar};
use group::Group;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use subtle::{ConditionallySelectable, ConstantTimeEq};

use std::ops::Neg;

pub const L: usize = 32;

struct Transcript {
    hasher: blake3::Hasher,
}

impl Transcript {
    fn new(label: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(label);
        Transcript { hasher }
    }

    fn with(label: &[u8], f: impl FnOnce(&mut Transcript)) -> Scalar {
        let mut transcript = Transcript::new(label);
        f(&mut transcript);
        transcript.challenge()
    }

    fn add_element(&mut self, element: &RistrettoPoint) {
        self.hasher
            .update(&bincode::serde::encode_to_vec(element, bincode::config::standard()).unwrap());
    }

    fn add_elements<'a>(&mut self, elements: impl Iterator<Item = &'a RistrettoPoint>) {
        for element in elements {
            self.add_element(element);
        }
    }

    fn add_scalar(&mut self, scalar: &Scalar) {
        self.hasher
            .update(&bincode::serde::encode_to_vec(scalar, bincode::config::standard()).unwrap());
    }

    fn rng(self) -> ChaCha20Rng {
        ChaCha20Rng::from_seed(*self.hasher.finalize().as_bytes())
    }

    fn challenge(self) -> Scalar {
        Scalar::random(&mut self.rng())
    }
}

#[derive(Serialize, Deserialize)]
pub struct PrivateKey {
    x: Scalar,
    public: PublicKey,
}

impl PrivateKey {
    pub fn random(mut rng: impl CryptoRngCore) -> Self {
        let x = Scalar::random(&mut rng);
        let public = PublicKey {
            w: RistrettoPoint::generator() * x,
        };
        PrivateKey { x, public }
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }
}

#[derive(Serialize, Deserialize)]
pub struct PublicKey {
    w: RistrettoPoint,
}

#[derive(Serialize, Deserialize)]
pub struct Params {
    h1: RistrettoPoint,
    h2: RistrettoPoint,
    h3: RistrettoPoint,
}

impl Default for Params {
    fn default() -> Self {
        let rng = ChaCha20Rng::from_seed(*blake3::hash(b"INNOCENCE").as_bytes());
        Self::random(rng)
    }
}

impl Params {
    fn random(mut rng: impl CryptoRngCore) -> Self {
        Params {
            h1: RistrettoPoint::random(&mut rng),
            h2: RistrettoPoint::random(&mut rng),
            h3: RistrettoPoint::random(&mut rng),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct PreIssuance {
    r: Scalar,
    k: Scalar,
}

#[derive(Serialize, Deserialize)]
pub struct IssuanceRequest {
    big_k: RistrettoPoint,
    gamma: Scalar,
    k_bar: Scalar,
    r_bar: Scalar,
}

#[derive(Serialize, Deserialize)]
pub struct CreditToken {
    a: RistrettoPoint,
    e: Scalar,
    k: Scalar,
    r: Scalar,
    c: Scalar,
}

impl PreIssuance {
    pub fn random(mut rng: impl CryptoRngCore) -> Self {
        PreIssuance {
            r: Scalar::random(&mut rng),
            k: Scalar::random(&mut rng),
        }
    }

    pub fn request(&self, mut rng: impl CryptoRngCore) -> IssuanceRequest {
        let params = Params::default();

        let big_k = params.h2 * self.k + params.h3 * self.r;
        let k_prime = Scalar::random(&mut rng);
        let r_prime = Scalar::random(&mut rng);
        let k1 = params.h2 * k_prime + params.h3 * r_prime;

        let gamma = Transcript::with(b"request", |transcript| {
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

    pub fn to_credit_token(
        &self,
        public: &PublicKey,
        request: &IssuanceRequest,
        response: &IssuanceResponse,
    ) -> Option<CreditToken> {
        let params = Params::default();

        let x_a = RistrettoPoint::generator() + params.h1 * response.c + request.big_k;
        let x_g = RistrettoPoint::generator() * response.e + public.w;
        let y_a = response.a * response.z + x_a * response.gamma.neg();
        let y_g = RistrettoPoint::generator() * response.z + x_g * response.gamma.neg();

        let gamma = Transcript::with(b"respond", |transcript| {
            transcript.add_scalar(&response.e);
            transcript.add_elements([&response.a, &x_a, &x_g, &y_a, &y_g].into_iter());
        });

        if gamma != response.gamma {
            return None;
        }

        Some(CreditToken {
            a: response.a,
            e: response.e,
            r: self.r,
            k: self.k,
            c: response.c,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct IssuanceResponse {
    a: RistrettoPoint,
    e: Scalar,
    gamma: Scalar,
    z: Scalar,
    c: Scalar,
}

impl PrivateKey {
    pub fn issue(
        &self,
        request: &IssuanceRequest,
        c: Scalar,
        mut rng: impl CryptoRngCore,
    ) -> Option<IssuanceResponse> {
        let params = Params::default();
        let k1 =
            (params.h2 * request.k_bar + params.h3 * request.r_bar) - request.big_k * request.gamma;

        let gamma = Transcript::with(b"request", |transcript| {
            transcript.add_elements([&request.big_k, &k1].into_iter());
        });

        if gamma != request.gamma {
            return None;
        }

        let e = Scalar::random(&mut rng);
        let x_a = RistrettoPoint::generator() + params.h1 * c + request.big_k;
        let a = x_a * (e + self.x).invert();
        let x_g = RistrettoPoint::generator() * e + self.public.w;
        let alpha = Scalar::random(&mut rng);
        let y_a = a * alpha;
        let y_g = RistrettoPoint::generator() * alpha;

        let gamma = Transcript::with(b"respond", |transcript| {
            transcript.add_scalar(&e);
            transcript.add_elements([&a, &x_a, &x_g, &y_a, &y_g].into_iter());
        });

        let z = gamma * (self.x + e) + alpha;

        Some(IssuanceResponse { a, e, gamma, z, c })
    }
}

#[derive(Serialize, Deserialize)]
pub struct SpendProof {
    k: Scalar,
    s: Scalar,
    a_prime: RistrettoPoint,
    b_bar: RistrettoPoint,
    com: [RistrettoPoint; L],
    gamma: Scalar,
    e_bar: Scalar,
    r2_bar: Scalar,
    r3_bar: Scalar,
    c_bar: Scalar,
    r_bar: Scalar,
    w00: Scalar,
    w01: Scalar,
    gamma0: [Scalar; L],
    z: [[Scalar; 2]; L],
    k_bar: Scalar,
    s_bar: Scalar,
}

impl SpendProof {
    pub fn nonce(&self) -> Scalar {
        self.k
    }

    pub fn charge(&self) -> Scalar {
        self.s
    }
}

impl PrivateKey {
    pub fn refund(&self, spend_proof: &SpendProof, mut rng: impl CryptoRngCore) -> Option<Refund> {
        let params = Params::default();

        if spend_proof.a_prime == RistrettoPoint::generator() {
            return None;
        }

        let a_bar = spend_proof.a_prime * self.x;
        let big_h1 = RistrettoPoint::generator() + params.h2 * spend_proof.k;
        let a1 = spend_proof.a_prime * spend_proof.e_bar
            + spend_proof.b_bar * spend_proof.r2_bar
            + a_bar * spend_proof.gamma.neg();
        let a2 = spend_proof.b_bar * spend_proof.r3_bar
            + params.h1 * spend_proof.c_bar
            + params.h3 * spend_proof.r_bar
            + big_h1 * spend_proof.gamma.neg();
        let mut gamma01 = [Scalar::ZERO; L];
        gamma01[0] = spend_proof.gamma - spend_proof.gamma0[0];
        let mut big_c = [[RistrettoPoint::identity(); 2]; L];
        big_c[0][0] = spend_proof.com[0];
        big_c[0][1] = spend_proof.com[0] - params.h1;
        let mut big_c_prime = [[RistrettoPoint::identity(); 2]; L];
        big_c_prime[0][0] = params.h2 * spend_proof.w00 + params.h3 * spend_proof.z[0][0]
            - big_c[0][0] * spend_proof.gamma0[0];
        big_c_prime[0][1] = params.h2 * spend_proof.w01 + params.h3 * spend_proof.z[0][1]
            - big_c[0][1] * gamma01[1];
        for j in 1..L {
            gamma01[j] = spend_proof.gamma - spend_proof.gamma0[j];
            big_c[j][0] = spend_proof.com[j];
            big_c[j][1] = spend_proof.com[j] - params.h1;
            big_c_prime[j][0] =
                params.h3 * spend_proof.z[j][0] - big_c[j][0] * spend_proof.gamma0[j];
            big_c_prime[j][1] = params.h3 * spend_proof.z[j][1] - big_c[j][1] * gamma01[j];
        }

        let k_prime = (0..L)
            .map(|i| spend_proof.com[i] * Scalar::from(2u64.pow(i as u32)))
            .fold(RistrettoPoint::identity(), |a, b| a + b);
        let com_ = params.h1 * spend_proof.s + k_prime;
        let big_c = params.h1 * spend_proof.c_bar
            + params.h2 * spend_proof.k_bar
            + params.h3 * spend_proof.s_bar
            - com_ * spend_proof.gamma;

        let gamma = Transcript::with(b"spend", |transcript| {
            transcript.add_scalar(&spend_proof.k);
            transcript.add_elements([&spend_proof.a_prime, &spend_proof.b_bar].into_iter());
            transcript.add_elements([&a1, &a2].into_iter());
            transcript.add_elements(spend_proof.com.iter());
            for i in 0..L {
                transcript.add_elements(big_c_prime[i].iter());
            }
            transcript.add_element(&big_c);
        });

        // TODO go through each of the fields to see which aren't being computed correctly
        if gamma != spend_proof.gamma {
            return None;
        }

        todo!()
    }
}

#[derive(Serialize, Deserialize)]
pub struct PreRefund {
    r: Scalar,
    k: Scalar,
    m: Scalar,
}

fn bits_of(s: Scalar) -> [Scalar; L] {
    let bytes = s.as_bytes();
    let mut result = [Scalar::ZERO; L];

    for i in 0..L {
        let b = i / 8;
        let j = i % 8;
        result[i] = Scalar::from((bytes[b] & (0b00000001 << j)) as u64);
    }

    result
}

impl CreditToken {
    // precondition: 2^L > self.c >= s
    pub fn prove_spend(
        &self,
        s: Scalar,
        public_key: &PublicKey,
        mut rng: impl CryptoRngCore,
    ) -> (SpendProof, PreRefund) {
        let params = Params::default();

        let r1 = Scalar::random(&mut rng);
        let r2 = Scalar::random(&mut rng);
        let c_prime = Scalar::random(&mut rng);
        let r_prime = Scalar::random(&mut rng);
        let e_prime = Scalar::random(&mut rng);
        let r2_prime = Scalar::random(&mut rng);
        let r3_prime = Scalar::random(&mut rng);

        let b = RistrettoPoint::generator()
            + params.h1 * self.c
            + params.h2 * self.k
            + params.h3 * self.r;
        let a_prime = self.a * (r1 * r2);
        let b_bar = b * r1;
        let r3 = r1.invert();
        let a1 = a_prime * e_prime + b_bar * r2_prime;
        let a2 = b_bar * r3_prime + params.h1 * c_prime + params.h3 * r_prime;

        let i = bits_of(self.c - s);

        let k_star = Scalar::random(&mut rng);
        let mut s_i = Vec::with_capacity(L);
        for _ in 0..L {
            s_i.push(Scalar::random(&mut rng));
        }
        let mut com = [RistrettoPoint::identity(); L];
        com[0] = params.h1 * i[0] + params.h2 * k_star + params.h3 * s_i[0];
        for j in 1..L {
            com[j] = params.h1 * i[j] + params.h3 * s_i[j];
        }
        let mut big_c = [[RistrettoPoint::identity(); 2]; L];
        let mut big_c_prime = [[RistrettoPoint::identity(); 2]; L];
        let mut gamma = [Scalar::ZERO; L];

        big_c[0][0] = com[0];
        big_c[0][1] = com[0] - params.h1;
        let k0_prime = Scalar::random(&mut rng);
        let mut s_i_prime = [Scalar::ZERO; L];
        for i in 0..L {
            s_i_prime[i] = Scalar::random(&mut rng);
        }
        let mut gamma_i = [Scalar::ZERO; L];
        gamma_i[0] = Scalar::random(&mut rng);
        let w0 = Scalar::random(&mut rng);
        let mut z = [Scalar::ZERO; L];
        z[0] = Scalar::random(&mut rng);

        let b0 = params.h2 * k0_prime + params.h3 * s_i_prime[0];
        let b1 = params.h2 * w0 + params.h3 * z[0] - big_c[0][0] * gamma_i[0];

        big_c_prime[0][0] = RistrettoPoint::conditional_select(&b0, &b1, i[0].ct_eq(&Scalar::ZERO));

        big_c_prime[0][1] = RistrettoPoint::conditional_select(&b1, &b0, i[0].ct_eq(&Scalar::ZERO));

        for j in 1..L {
            big_c[j][0] = com[j];
            big_c[j][1] = com[j] - params.h1;
            let s_j_prime = Scalar::random(&mut rng);
            gamma_i[j] = Scalar::random(&mut rng);
            z[j] = Scalar::random(&mut rng);

            let b0 = params.h3 * s_j_prime;
            let b1 = params.h3 * z[j] - big_c[j][0] * gamma_i[j];

            big_c_prime[j][0] =
                RistrettoPoint::conditional_select(&b0, &b1, i[j].ct_eq(&Scalar::ZERO));
            big_c_prime[j][1] =
                RistrettoPoint::conditional_select(&b1, &b0, i[j].ct_eq(&Scalar::ZERO));
        }
        let r_star = (0..L)
            .map(|i| s_i[i] * Scalar::from(2u32.pow(i as u32)))
            .fold(Scalar::ZERO, |x, y| x + y);
        let k_prime = Scalar::random(&mut rng);
        let s_prime = Scalar::random(&mut rng);
        let c_ = params.h1 * c_prime + params.h2 * k_prime + params.h3 * s_prime;

        let gamma = Transcript::with(b"spend", |transcript| {
            transcript.add_scalar(&self.k);
            transcript.add_elements([&a_prime, &b_bar].into_iter());
            transcript.add_elements([&a1, &a2].into_iter());
            transcript.add_elements(com.iter());
            for i in 0..L {
                transcript.add_elements(big_c_prime[i].iter());
            }
            transcript.add_element(&c_);
        });

        let e_bar = gamma.neg() * self.e + e_prime;
        let r2_bar = gamma.neg() * r2 + r2_prime;
        let r3_bar = gamma.neg() * r3 + r3_prime;
        let c_bar = gamma.neg() * self.c + c_prime;
        let r_bar = gamma.neg() * self.r + r_prime;
        let mut gamma00 = [Scalar::ZERO; L];
        gamma00[0] = Scalar::conditional_select(
            &(gamma - gamma_i[0]),
            &gamma_i[0],
            i[0].ct_eq(&Scalar::ZERO),
        );
        let w00 = Scalar::conditional_select(
            &(gamma00[0] * k_star + k0_prime),
            &z[0],
            i[0].ct_eq(&Scalar::ZERO),
        );
        let w01 = Scalar::conditional_select(
            &w0,
            &((gamma - gamma00[0]) * k_star + k0_prime),
            i[0].ct_eq(&Scalar::ZERO),
        );
        let mut z00 = [[Scalar::ZERO; 2]; L];
        z00[0][0] = Scalar::conditional_select(
            &(gamma00[0] * s_i[0] + s_i_prime[0]),
            &z[0],
            i[0].ct_eq(&Scalar::ZERO),
        );
        z00[0][1] = Scalar::conditional_select(
            &z[0],
            &(gamma00[0] * s_i[0] + s_i_prime[0]),
            i[0].ct_eq(&Scalar::ZERO),
        );
        for j in 1..L {
            gamma00[j] = Scalar::conditional_select(
                &(gamma - gamma_i[j]),
                &gamma_i[j],
                i[j].ct_eq(&Scalar::ZERO),
            );
            z00[j][0] = Scalar::conditional_select(
                &(gamma00[j] * s_i[j] + s_i_prime[j]),
                &z[j],
                i[j].ct_eq(&Scalar::ZERO),
            );
            z00[j][1] = Scalar::conditional_select(
                &z[j],
                &(gamma00[j] * s_i[j] + s_i_prime[j]),
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

#[derive(Serialize, Deserialize)]
pub struct Refund {}

impl PreRefund {
    pub fn to_credit_token(
        &self,
        _spend_proof: &SpendProof,
        _refund: &Refund,
        _public_key: &PublicKey,
    ) -> Option<CreditToken> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuance() {
        use rand_core::OsRng;
        for _i in 0..100 {
            let private_key = PrivateKey::random(OsRng);
            let preissuance = PreIssuance::random(OsRng);
            let issuance_request = preissuance.request(OsRng);
            let issuance_response = private_key
                .issue(&issuance_request, Scalar::from(20u64), OsRng)
                .unwrap();
            let _credit_token1 = preissuance
                .to_credit_token(private_key.public(), &issuance_request, &issuance_response)
                .unwrap();
        }
    }

    #[test]
    fn full_cycle() {
        use rand_core::OsRng;
        for _i in 0..100 {
            let private_key = PrivateKey::random(OsRng);
            let preissuance = PreIssuance::random(OsRng);
            let issuance_request = preissuance.request(OsRng);
            let issuance_response = private_key
                .issue(&issuance_request, Scalar::from(20u64), OsRng)
                .unwrap();
            let credit_token1 = preissuance
                .to_credit_token(private_key.public(), &issuance_request, &issuance_response)
                .unwrap();
            let charge = Scalar::from(20u64);
            let (spend_proof, prerefund) =
                credit_token1.prove_spend(charge, private_key.public(), OsRng);
            let refund = private_key.refund(&spend_proof, OsRng).unwrap();
            let credit_token2 = prerefund
                .to_credit_token(&spend_proof, &refund, private_key.public())
                .unwrap();
            let charge = Scalar::from(20u64);
            let (spend_proof, prerefund) =
                credit_token2.prove_spend(charge, private_key.public(), OsRng);
            let refund = private_key.refund(&spend_proof, OsRng).unwrap();
            let _credit_token3 = prerefund
                .to_credit_token(&spend_proof, &refund, private_key.public())
                .unwrap();
        }
    }
}
