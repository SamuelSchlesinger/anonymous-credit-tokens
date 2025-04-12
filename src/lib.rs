use curve25519_dalek::{RistrettoPoint, Scalar};
use rand_core::{SeedableRng, CryptoRngCore};
use rand_chacha::ChaCha20Rng;
use group::Group;
use serde::{Deserialize, Serialize};

use std::ops::Neg;

struct Transcript {
    hasher: blake3::Hasher,
}

impl Transcript {
    fn new(label: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(label);
        Transcript {
            hasher,
        }
    }

    fn add_element(&mut self, element: &RistrettoPoint) {
        self.hasher.update(&bincode::serde::encode_to_vec(element, bincode::config::standard()).unwrap());
    }

    fn add_scalar(&mut self, scalar: &Scalar) {
        self.hasher.update(&bincode::serde::encode_to_vec(scalar, bincode::config::standard()).unwrap());
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
        PrivateKey {
            x,
            public,
        }
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
    h0: RistrettoPoint,
    h1: RistrettoPoint,
    h2: RistrettoPoint,
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
            h0: RistrettoPoint::random(&mut rng),
            h1: RistrettoPoint::random(&mut rng),
            h2: RistrettoPoint::random(&mut rng),
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
    kr: RistrettoPoint,
    c: Scalar,
    r_z: Scalar,
    k_z: Scalar,
}

#[derive(Serialize, Deserialize)]
pub struct Credential {
    a: RistrettoPoint,
    e: Scalar,
    k: Scalar,
    r: Scalar,
    n: Scalar,
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
        let mut transcript = Transcript::new(b"request");
        let kr = params.h0 * self.r + params.h1 * self.k;
        transcript.add_element(&kr);
        let r_t = Scalar::random(&mut rng);
        let k_t = Scalar::random(&mut rng);
        let kr_t = params.h0 * r_t + params.h1 * k_t;
        transcript.add_element(&kr_t);

        let c = transcript.challenge();

        let r_z = r_t + self.r * c;
        let k_z = k_t + self.k * c;

        IssuanceRequest {
            kr,
            c,
            r_z,
            k_z,
        }
    }

    pub fn credential(&self, public: &PublicKey, request: &IssuanceRequest, response: &IssuanceResponse) -> Option<Credential> {
        let params = Params::default();
        let mut transcript = Transcript::new(b"respond");
        transcript.add_scalar(&response.e);
        transcript.add_element(&response.a);

        let x_a = RistrettoPoint::generator() + request.kr + params.h2 * response.n;
        transcript.add_element(&x_a);
        let x_g = RistrettoPoint::generator() * response.e + public.w;
        transcript.add_element(&x_g);

        let y_a_prime = response.a * response.z + x_a * response.c.neg();
        transcript.add_element(&y_a_prime);
        let y_g_prime = RistrettoPoint::generator() * response.z + x_g * response.c.neg();
        transcript.add_element(&y_g_prime);

        let c = transcript.challenge();

        if c != response.c {
            return None;
        }

        Some(Credential {
            a: response.a, e: response.e, r: self.r, k: self.k, n: response.n,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct IssuanceResponse {
    a: RistrettoPoint,
    e: Scalar,
    c: Scalar,
    z: Scalar,
    n: Scalar,
}

impl PrivateKey {
    pub fn respond(&self, request: &IssuanceRequest, n: Scalar, mut rng: impl CryptoRngCore) -> Option<IssuanceResponse> {
        let params = Params::default();
        let mut transcript = Transcript::new(b"request");
        transcript.add_element(&request.kr);
        let kr_t = (params.h0 * request.r_z + params.h1 * request.k_z) - request.kr * request.c;
        transcript.add_element(&kr_t);
        let c = transcript.challenge();

        if c != request.c {
            return None;
        }

        let mut transcript = Transcript::new(b"respond");

        let e = Scalar::random(&mut rng);
        transcript.add_scalar(&e);

        let a = (RistrettoPoint::generator() + request.kr + params.h2 * n) * (e + self.x).invert();
        transcript.add_element(&a);

        let x_a = RistrettoPoint::generator() + request.kr + params.h2 * n;
        transcript.add_element(&x_a);
        let x_g = RistrettoPoint::generator() * e + self.public.w;
        transcript.add_element(&x_g);

        let alpha = Scalar::random(&mut rng);

        let y_a = a * alpha;
        transcript.add_element(&y_a);
        let y_g = RistrettoPoint::generator() * alpha;
        transcript.add_element(&y_g);

        let c = transcript.challenge();

        let z = c * (self.x + e) + alpha;

        Some(IssuanceResponse {
            a,
            e,
            c,
            z,
            n,
        })
    }
}

#[test]
fn create_credential() {
    use rand_core::OsRng;
    let private_key = PrivateKey::random(OsRng);
    let pre_issuance = PreIssuance::random(OsRng);
    let req = pre_issuance.request(OsRng);
    let resp = private_key.respond(&req, Scalar::from(20u64), OsRng).unwrap();
    let cred = pre_issuance.credential(private_key.public(), &req, &resp).unwrap();
}
