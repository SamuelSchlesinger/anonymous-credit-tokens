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

use crate::*;
use group::Group;
use proptest::prelude::*;
use rand_core::OsRng;
use std::collections::HashSet;

/// The digit count used throughout these tests (except the genericity
/// test, which exercises several).
const D: usize = 8;
/// The maximum credit amount at the test digit count.
const MAX_CREDITS: u128 = Params::<D>::MAX_CREDITS;

// Configure proptest to run fewer cases for faster testing.
fn fast_config() -> ProptestConfig {
    ProptestConfig::with_cases(8)
}

/// A simple in-memory nullifier database for testing double-spend prevention
#[derive(Default)]
struct NullifierDb {
    used_nullifiers: HashSet<Scalar>,
}

impl NullifierDb {
    fn new() -> Self {
        Self {
            used_nullifiers: HashSet::new(),
        }
    }

    fn is_spent(&self, nullifier: &Scalar) -> bool {
        self.used_nullifiers.contains(nullifier)
    }

    fn record_spent(&mut self, nullifier: &Scalar) {
        self.used_nullifiers.insert(*nullifier);
    }
}

fn test_params() -> Params<D> {
    Params::new("test-org", "test-service", "test-env", "2024-01-01")
}

fn test_ctx() -> Scalar {
    Scalar::from(20250710u64)
}

/// Runs the full issuance protocol and returns the resulting token.
fn issue_token<const DD: usize>(
    params: &Params<DD>,
    private_key: &PrivateKey,
    c: u128,
    ctx: Scalar,
) -> CreditToken {
    let pre_issuance = PreIssuance::random(OsRng);
    let request = pre_issuance.request(params, OsRng);
    let response = private_key.issue(params, &request, c, ctx, OsRng).unwrap();
    pre_issuance
        .to_credit_token(params, private_key.public(), &request, &response, ctx)
        .unwrap()
}

/// Runs one spend/refund round trip and returns the new token.
fn spend_round<const DD: usize>(
    params: &Params<DD>,
    private_key: &PrivateKey,
    token: &CreditToken,
    s: u128,
    a: u128,
    t: u128,
) -> Result<CreditToken, Error> {
    let (spend_proof, prerefund) = token.prove_spend(params, s, a, OsRng)?;
    let refund = private_key.refund(params, &spend_proof, t, OsRng)?;
    prerefund.to_credit_token(params, &spend_proof, &refund, private_key.public())
}

/// Recomposes an array of base-3 digit scalars into an integer.
fn recompose_trits(digits: &[Scalar; D]) -> u128 {
    let mut acc: u128 = 0;
    for d in digits.iter().rev() {
        let bytes = d.as_bytes();
        assert!(bytes[0] <= 2 && bytes[1..].iter().all(|&b| b == 0));
        acc = acc * 3 + bytes[0] as u128;
    }
    acc
}

// ===== PARAMETERS =====

#[test]
fn test_params_generation_deterministic() {
    let params1: Params<D> = Params::new("org", "svc", "prod", "2024-01-01");
    let params2: Params<D> = Params::new("org", "svc", "prod", "2024-01-01");
    assert_eq!(params1, params2);

    // Any change to the domain separator changes the parameters.
    let params3: Params<D> = Params::new("org", "svc", "prod", "2024-01-02");
    assert_ne!(params1, params3);
    let params4: Params<D> = Params::new("org", "svc", "staging", "2024-01-01");
    assert_ne!(params1, params4);
}

#[test]
fn test_params_generators_distinct() {
    let params = test_params();
    let g = RistrettoPoint::generator();
    let points = [
        g,
        params.h1.basepoint(),
        params.h2.basepoint(),
        params.h3.basepoint(),
        params.h4.basepoint(),
    ];
    for i in 0..points.len() {
        for j in (i + 1)..points.len() {
            assert_ne!(points[i], points[j], "generators {} and {} collide", i, j);
        }
    }
}

#[test]
fn test_long_domain_separator_does_not_panic() {
    // A domain separator long enough to push the hash-to-group DST past 255
    // bytes must be handled via RFC 9380's oversized-DST reduction, not panic.
    let long = "x".repeat(300);
    let params: Params<D> = Params::from_domain_separator(long.as_bytes());
    let params2: Params<D> = Params::from_domain_separator(long.as_bytes());
    assert_eq!(params, params2);
}

// ===== TERNARY DECOMPOSITION =====

#[test]
fn test_max_credits_constant() {
    let mut expected: u128 = 1;
    for _ in 0..D {
        expected *= 3;
    }
    assert_eq!(MAX_CREDITS, expected - 1);
    // MAX_CREDITS must fit the u128 credit encoding with room for c + a.
    const _: () = assert!(MAX_CREDITS < (1u128 << 127));
}

#[test]
fn test_trit_decompose_edges() {
    for v in [
        0u128,
        1,
        2,
        3,
        4,
        5,
        26,
        27,
        3u128.pow(D as u32 - 1),
        MAX_CREDITS - 1,
        MAX_CREDITS,
    ] {
        let digits = trits_of(&Scalar::from(v));
        assert_eq!(recompose_trits(&digits), v, "roundtrip failed for {}", v);
    }

    // MAX_CREDITS = 3^D - 1 decomposes to all-2 digits.
    let digits = trits_of::<D>(&Scalar::from(MAX_CREDITS));
    for d in digits.iter() {
        assert_eq!(*d, Scalar::from(2u64));
    }
}

// ===== ISSUANCE =====

#[test]
fn test_issuance_flow() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let ctx = test_ctx();

    let token = issue_token(&params, &private_key, 100, ctx);
    assert_eq!(token.credits(), Scalar::from(100u64));
    assert_eq!(token.context(), ctx);
}

#[test]
fn test_issuance_amount_too_big() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let pre_issuance = PreIssuance::random(OsRng);
    let request = pre_issuance.request(&params, OsRng);

    // MAX_CREDITS is fine; MAX_CREDITS + 1 is not.
    assert!(
        private_key
            .issue(&params, &request, MAX_CREDITS, test_ctx(), OsRng)
            .is_ok()
    );
    assert_eq!(
        private_key
            .issue(&params, &request, MAX_CREDITS + 1, test_ctx(), OsRng)
            .err(),
        Some(Error::AmountTooBigError)
    );
}

#[test]
fn test_issuance_wrong_context_rejected() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let pre_issuance = PreIssuance::random(OsRng);
    let request = pre_issuance.request(&params, OsRng);
    let response = private_key
        .issue(&params, &request, 50, test_ctx(), OsRng)
        .unwrap();

    // The client verifying under a different context must reject.
    let wrong_ctx = test_ctx() + Scalar::ONE;
    assert_eq!(
        pre_issuance
            .to_credit_token(
                &params,
                private_key.public(),
                &request,
                &response,
                wrong_ctx
            )
            .err(),
        Some(Error::InvalidIssuanceResponseProof)
    );
}

#[test]
fn test_issuance_tampered_request_rejected() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let pre_issuance = PreIssuance::random(OsRng);
    let mut request = pre_issuance.request(&params, OsRng);
    request.big_k += RistrettoPoint::generator();

    assert_eq!(
        private_key
            .issue(&params, &request, 50, test_ctx(), OsRng)
            .err(),
        Some(Error::InvalidIssuanceRequestProof)
    );
}

// ===== SPENDING AND REFUNDS =====

#[test]
fn test_spend_and_refund() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let token = issue_token(&params, &private_key, 100, test_ctx());

    // Spend 30, no top-up, no partial refund: balance 70.
    let token = spend_round(&params, &private_key, &token, 30, 0, 0).unwrap();
    assert_eq!(token.credits(), Scalar::from(70u64));

    // Spend the exact remaining balance: balance 0.
    let token = spend_round(&params, &private_key, &token, 70, 0, 0).unwrap();
    assert_eq!(token.credits(), Scalar::ZERO);

    // A zero-value spend from an empty token still works.
    let token = spend_round(&params, &private_key, &token, 0, 0, 0).unwrap();
    assert_eq!(token.credits(), Scalar::ZERO);

    // Overspending fails client-side.
    assert_eq!(
        token.prove_spend(&params, 1, 0, OsRng).err(),
        Some(Error::InvalidAmount)
    );
}

#[test]
fn test_partial_refund_bounds() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let token = issue_token(&params, &private_key, 100, test_ctx());

    // The issuer decides t after seeing the proof; t = s is allowed
    // (charging nothing), t = s + 1 is not.
    let (spend_proof, prerefund) = token.prove_spend(&params, 30, 0, OsRng).unwrap();
    assert_eq!(
        private_key.refund(&params, &spend_proof, 31, OsRng).err(),
        Some(Error::InvalidRefundAmount)
    );
    let refund = private_key
        .refund(&params, &spend_proof, 30, OsRng)
        .unwrap();
    let token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();
    assert_eq!(token.credits(), Scalar::from(100u64));

    // A strictly partial refund: charge 30, return 10, net charge 20.
    let token = spend_round(&params, &private_key, &token, 30, 0, 10).unwrap();
    assert_eq!(token.credits(), Scalar::from(80u64));
}

#[test]
fn test_topup_basic() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let token = issue_token(&params, &private_key, 100, test_ctx());

    // Spend 30 while topping up 50: the issuer grants the top-up by
    // setting the return amount t = a = 50, so the new balance is
    // 100 - 30 + 50 = 120.
    let (spend_proof, prerefund) = token.prove_spend(&params, 30, 50, OsRng).unwrap();
    assert_eq!(spend_proof.charge(), Scalar::from(30u64));
    assert_eq!(spend_proof.topup(), Scalar::from(50u64));
    let refund = private_key
        .refund(&params, &spend_proof, 50, OsRng)
        .unwrap();
    let token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();
    assert_eq!(token.credits(), Scalar::from(120u64));

    // The new token spends normally.
    let token = spend_round(&params, &private_key, &token, 120, 0, 0).unwrap();
    assert_eq!(token.credits(), Scalar::ZERO);
}

#[test]
fn test_topup_clawback() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let token = issue_token(&params, &private_key, 100, test_ctx());

    // The issuer declines a declared top-up (e.g., the out-of-band payment
    // failed) by setting t = 0: the client is charged the spend and gains
    // nothing.
    let (spend_proof, prerefund) = token.prove_spend(&params, 30, 50, OsRng).unwrap();
    let refund = private_key.refund(&params, &spend_proof, 0, OsRng).unwrap();
    let token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();
    assert_eq!(token.credits(), Scalar::from(70u64));
}

#[test]
fn test_spend_beyond_balance_rejected_even_with_topup() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let token = issue_token(&params, &private_key, 10, test_ctx());

    // The floor range proof requires s <= c regardless of the top-up:
    // spends are covered by the balance alone.
    assert_eq!(
        token.prove_spend(&params, 200, 300, OsRng).err(),
        Some(Error::InvalidAmount)
    );
    assert_eq!(
        token.prove_spend(&params, 11, 1, OsRng).err(),
        Some(Error::InvalidAmount)
    );
}

#[test]
fn test_topup_exceeding_max_rejected() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let token = issue_token(&params, &private_key, 10, test_ctx());

    // Amounts above MAX_CREDITS are rejected outright.
    assert_eq!(
        token.prove_spend(&params, 0, MAX_CREDITS + 1, OsRng).err(),
        Some(Error::InvalidAmount)
    );
    assert_eq!(
        token.prove_spend(&params, MAX_CREDITS + 1, 0, OsRng).err(),
        Some(Error::InvalidAmount)
    );
    // A top-up that would push the balance past MAX_CREDITS is rejected.
    assert_eq!(
        token.prove_spend(&params, 0, MAX_CREDITS, OsRng).err(),
        Some(Error::InvalidAmount)
    );
}

#[test]
fn test_settlement_corridor() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let token = issue_token(&params, &private_key, 100, test_ctx());

    // With s = 50 and a = 20, the return amount ranges over [0, 70]:
    // the corridor of reachable balances is [50, 120].
    let (spend_proof, prerefund) = token.prove_spend(&params, 50, 20, OsRng).unwrap();
    assert_eq!(
        private_key.refund(&params, &spend_proof, 71, OsRng).err(),
        Some(Error::InvalidRefundAmount)
    );
    // The upper endpoint: full refund plus the whole top-up, landing on the
    // ceiling-proved balance c + a = 120, above the original balance.
    let refund = private_key
        .refund(&params, &spend_proof, 70, OsRng)
        .unwrap();
    let token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();
    assert_eq!(token.credits(), Scalar::from(120u64));

    // The lower endpoint: t = 0 lands on the floor-proved balance c - s.
    let (spend_proof, prerefund) = token.prove_spend(&params, 50, 20, OsRng).unwrap();
    let refund = private_key.refund(&params, &spend_proof, 0, OsRng).unwrap();
    let token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();
    assert_eq!(token.credits(), Scalar::from(70u64));

    // An interior point: grant the top-up and refund 10 of the spend.
    let (spend_proof, prerefund) = token.prove_spend(&params, 50, 20, OsRng).unwrap();
    let refund = private_key
        .refund(&params, &spend_proof, 30, OsRng)
        .unwrap();
    let token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();
    // 70 - 50 + 30 = 50.
    assert_eq!(token.credits(), Scalar::from(50u64));
}

// ===== AMOUNT VALIDATION AND WRAPAROUND =====

/// A malicious client crafts a spend whose public amount wraps around the
/// group order: with balance c and claimed post-spend balance v1, the scalar
/// relation v1 = c - s (mod q) holds for s = c - v1 mod q even when v1 is
/// enormous. The sigma protocol proof VERIFIES (the relation is true in the
/// scalar field); only the issuer's integer validation of s blocks the attack.
#[test]
fn test_wraparound_attack_is_blocked_by_amount_validation() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let token = issue_token(&params, &private_key, 5, test_ctx());

    // Claim the maximum possible post-spend balance.
    let v1_target = MAX_CREDITS;
    let digits1 = trits_of(&Scalar::from(v1_target));
    // The ceiling decomposition stays honest: v2 = c + 0 = 5.
    let digits2 = trits_of(&Scalar::from(5u64));
    // s = c - v1 mod q: a "spend" that inflates the balance to v1_target.
    let s_scalar = Scalar::from(5u64) - Scalar::from(v1_target);
    let (spend_proof, _prerefund) = token
        .prove_spend_with_digits(&params, s_scalar, Scalar::ZERO, &digits1, &digits2, OsRng)
        .unwrap();

    // Demonstrate the attack is real at the proof layer: the sigma protocol
    // statement is satisfied, so verification alone accepts it.
    let a_bar = spend_proof.a_prime * private_key.x;
    let statement = spend_statement(
        &params,
        &spend_proof.k,
        &spend_proof.s,
        &spend_proof.a,
        &spend_proof.ctx,
        &spend_proof.a_prime,
        &spend_proof.b_bar,
        &a_bar,
        &spend_proof.com1,
        &spend_proof.t1,
        &spend_proof.com2,
        &spend_proof.t2,
        &spend_proof.k_n,
    );
    let verifier = statement
        .into_nizk_with_protocol_id(
            &session(
                &params,
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
        .unwrap();
    assert!(
        verifier.verify_compact(&spend_proof.pok).is_ok(),
        "the wrapped-amount proof verifies; validation must catch it"
    );

    // The issuer's amount validation rejects it before accepting the spend.
    assert_eq!(
        private_key.refund(&params, &spend_proof, 0, OsRng).err(),
        Some(Error::ScalarOutOfRangeError)
    );
}

/// Same idea with the top-up amount: a top-up scalar that wraps around the
/// group order (here a = -1 mod q, a "negative top-up") satisfies the scalar
/// relation v2 = c + a (mod q) with v2 = 4, but must be rejected by the
/// issuer's integer validation of a.
#[test]
fn test_wraparound_topup_is_blocked_by_amount_validation() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let token = issue_token(&params, &private_key, 5, test_ctx());

    // With s = 0 the floor decomposition stays honest: v1 = 5. With
    // a = -1 mod q, the claimed topped-up balance v2 = 5 - 1 = 4 satisfies
    // v2 = c + a in the scalar field.
    let digits1 = trits_of(&Scalar::from(5u64));
    let digits2 = trits_of(&Scalar::from(4u64));
    let a_scalar = Scalar::ZERO - Scalar::ONE;
    let (spend_proof, _) = token
        .prove_spend_with_digits(&params, Scalar::ZERO, a_scalar, &digits1, &digits2, OsRng)
        .unwrap();

    // a does not decode as a credit amount, so the issuer rejects it
    // before looking at the proof.
    assert_eq!(
        private_key.refund(&params, &spend_proof, 0, OsRng).err(),
        Some(Error::ScalarOutOfRangeError)
    );
}

/// The public spend amount s and top-up amount a are each bound by the proof,
/// not merely their difference. A man-in-the-middle who shifts (s, a) by a
/// common delta preserves the new balance v = c - s + a but must not produce a
/// verifying proof, otherwise the charge and top-up the issuer records could be
/// inflated without the client's consent.
#[test]
fn test_spend_amounts_are_individually_bound() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let token = issue_token(&params, &private_key, 100, test_ctx());

    let (spend_proof, _) = token.prove_spend(&params, 30, 10, OsRng).unwrap();
    // Baseline: the honest proof verifies.
    assert!(private_key.refund(&params, &spend_proof, 0, OsRng).is_ok());

    // Shift (s, a) -> (s + 5, a + 5): under the dual-proof statement each
    // amount is constrained by its own consistency equation, so the shifted
    // pair must not verify.
    let mut shifted = spend_proof.clone();
    shifted.s += Scalar::from(5u64);
    shifted.a += Scalar::from(5u64);
    assert_eq!(
        private_key.refund(&params, &shifted, 0, OsRng).err(),
        Some(Error::InvalidClientSpendProof),
        "shifting (s, a) by a common delta must invalidate the proof"
    );

    // Shifting only s (changing v) must also fail.
    let mut only_s = spend_proof.clone();
    only_s.s += Scalar::from(1u64);
    assert_eq!(
        private_key.refund(&params, &only_s, 0, OsRng).err(),
        Some(Error::InvalidClientSpendProof)
    );
}

// ===== RANGE PROOF SOUNDNESS =====

/// A digit value outside {0, 1, 2} must not produce an acceptable proof:
/// the zero-constraint equation forces d(d-1)(d-2) = 0.
#[test]
fn test_forged_digit_rejected() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let token = issue_token(&params, &private_key, 3, test_ctx());

    // Represent the post-spend balance 3 as a single digit of value 3
    // instead of the honest [0, 1, 0, ...]. The consistency equation still
    // balances, so only the ternary constraint can catch this.
    let mut digits1 = [Scalar::ZERO; D];
    digits1[0] = Scalar::from(3u64);
    let digits2 = trits_of(&Scalar::from(3u64));

    // The proving backend may refuse to prove the false statement outright;
    // if it produced a proof, the issuer must reject it.
    if let Ok((spend_proof, _)) = token.prove_spend_with_digits(
        &params,
        Scalar::ZERO,
        Scalar::ZERO,
        &digits1,
        &digits2,
        OsRng,
    ) {
        assert_eq!(
            private_key.refund(&params, &spend_proof, 0, OsRng).err(),
            Some(Error::InvalidClientSpendProof)
        );
    }
}

// ===== PROOF INTEGRITY =====

#[test]
fn test_identity_a_prime_rejected() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let token = issue_token(&params, &private_key, 100, test_ctx());

    let (mut spend_proof, _) = token.prove_spend(&params, 10, 0, OsRng).unwrap();
    spend_proof.a_prime = RistrettoPoint::identity();
    assert_eq!(
        private_key.refund(&params, &spend_proof, 0, OsRng).err(),
        Some(Error::IdentityPointError)
    );
}

#[test]
fn test_tampered_spend_proof_rejected() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let token = issue_token(&params, &private_key, 100, test_ctx());
    let (spend_proof, _) = token.prove_spend(&params, 10, 5, OsRng).unwrap();

    // Baseline: the untampered proof is valid.
    assert!(private_key.refund(&params, &spend_proof, 0, OsRng).is_ok());

    // Tampering with any public input invalidates the proof.
    {
        let mut p = spend_proof.clone();
        p.s += Scalar::ONE;
        assert!(private_key.refund(&params, &p, 0, OsRng).is_err());
    }
    {
        let mut p = spend_proof.clone();
        p.a += Scalar::ONE;
        assert!(private_key.refund(&params, &p, 0, OsRng).is_err());
    }
    {
        let mut p = spend_proof.clone();
        p.ctx += Scalar::ONE;
        assert!(private_key.refund(&params, &p, 0, OsRng).is_err());
    }
    {
        let mut p = spend_proof.clone();
        p.k += Scalar::ONE;
        assert!(private_key.refund(&params, &p, 0, OsRng).is_err());
    }
    {
        let mut p = spend_proof.clone();
        p.b_bar += RistrettoPoint::generator();
        assert!(private_key.refund(&params, &p, 0, OsRng).is_err());
    }
    {
        let mut p = spend_proof.clone();
        p.com1[D - 1] += RistrettoPoint::generator();
        assert!(private_key.refund(&params, &p, 0, OsRng).is_err());
    }
    {
        let mut p = spend_proof.clone();
        p.t1[D / 2] += RistrettoPoint::generator();
        assert!(private_key.refund(&params, &p, 0, OsRng).is_err());
    }
    {
        let mut p = spend_proof.clone();
        p.com2[0] += RistrettoPoint::generator();
        assert!(private_key.refund(&params, &p, 0, OsRng).is_err());
    }
    {
        let mut p = spend_proof.clone();
        p.t2[D - 1] += RistrettoPoint::generator();
        assert!(private_key.refund(&params, &p, 0, OsRng).is_err());
    }
    {
        let mut p = spend_proof.clone();
        p.k_n += RistrettoPoint::generator();
        assert!(private_key.refund(&params, &p, 0, OsRng).is_err());
    }
    {
        let mut p = spend_proof.clone();
        let n = p.pok.len();
        p.pok[n / 2] ^= 0x01;
        assert!(private_key.refund(&params, &p, 0, OsRng).is_err());
    }
}

#[test]
fn test_wrong_issuer_key_rejects_spend() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let other_key = PrivateKey::random(OsRng);
    let token = issue_token(&params, &private_key, 100, test_ctx());
    let (spend_proof, _) = token.prove_spend(&params, 10, 0, OsRng).unwrap();

    assert_eq!(
        other_key.refund(&params, &spend_proof, 0, OsRng).err(),
        Some(Error::InvalidClientSpendProof)
    );
}

#[test]
fn test_tampered_refund_rejected() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let token = issue_token(&params, &private_key, 100, test_ctx());
    let (spend_proof, prerefund) = token.prove_spend(&params, 10, 0, OsRng).unwrap();
    let refund = private_key.refund(&params, &spend_proof, 5, OsRng).unwrap();

    // Baseline.
    assert!(
        prerefund
            .to_credit_token(&params, &spend_proof, &refund, private_key.public())
            .is_ok()
    );

    // Tampering with the refund amount, signature scalar, or point fails.
    {
        let mut r = refund.clone();
        r.t += Scalar::ONE;
        assert!(
            prerefund
                .to_credit_token(&params, &spend_proof, &r, private_key.public())
                .is_err()
        );
    }
    {
        let mut r = refund.clone();
        r.e += Scalar::ONE;
        assert_eq!(
            prerefund
                .to_credit_token(&params, &spend_proof, &r, private_key.public())
                .err(),
            Some(Error::InvalidRefundProof)
        );
    }
    {
        let mut r = refund.clone();
        r.a += RistrettoPoint::generator();
        assert_eq!(
            prerefund
                .to_credit_token(&params, &spend_proof, &r, private_key.public())
                .err(),
            Some(Error::InvalidRefundProof)
        );
    }
}

// ===== NULLIFIERS AND DOUBLE-SPENDING =====

#[test]
fn test_double_spend_detected_by_nullifier() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let mut db = NullifierDb::new();
    let token = issue_token(&params, &private_key, 100, test_ctx());

    // Two independent spends of the SAME token reveal the same nullifier.
    let (proof1, _) = token.prove_spend(&params, 10, 0, OsRng).unwrap();
    let (proof2, _) = token.prove_spend(&params, 20, 0, OsRng).unwrap();
    assert_eq!(proof1.nullifier(), proof2.nullifier());

    assert!(!db.is_spent(&proof1.nullifier()));
    db.record_spent(&proof1.nullifier());
    assert!(db.is_spent(&proof2.nullifier()), "double spend undetected");
}

#[test]
fn test_nullifier_chain_uniqueness() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let mut token = issue_token(&params, &private_key, 100, test_ctx());
    let mut seen = HashSet::new();

    for _ in 0..5 {
        let (spend_proof, prerefund) = token.prove_spend(&params, 10, 0, OsRng).unwrap();
        assert!(
            seen.insert(spend_proof.nullifier()),
            "nullifier repeated across the refund chain"
        );
        let refund = private_key.refund(&params, &spend_proof, 0, OsRng).unwrap();
        token = prerefund
            .to_credit_token(&params, &spend_proof, &refund, private_key.public())
            .unwrap();
    }
    assert_eq!(token.credits(), Scalar::from(50u64));
}

// ===== CONTEXT BINDING =====

#[test]
fn test_context_propagates_through_chain() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let ctx = test_ctx();
    let token = issue_token(&params, &private_key, 100, ctx);

    let (spend_proof, prerefund) = token.prove_spend(&params, 10, 0, OsRng).unwrap();
    assert_eq!(spend_proof.context(), ctx);
    let refund = private_key.refund(&params, &spend_proof, 0, OsRng).unwrap();
    let new_token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();
    assert_eq!(new_token.context(), ctx);
}

/// Pairing a stored PreRefund with a spend/refund from a different context is
/// detected: the refund token construction verifies against the context in the
/// client's own state, so a mispairing fails rather than minting an unspendable
/// token.
#[test]
fn test_prerefund_context_mispairing_rejected() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);

    // Two spends under different contexts.
    let token_a = issue_token(&params, &private_key, 100, Scalar::from(111u64));
    let token_b = issue_token(&params, &private_key, 100, Scalar::from(222u64));
    let (_proof_a, prerefund_a) = token_a.prove_spend(&params, 10, 0, OsRng).unwrap();
    let (proof_b, _prerefund_b) = token_b.prove_spend(&params, 10, 0, OsRng).unwrap();
    let refund_b = private_key.refund(&params, &proof_b, 0, OsRng).unwrap();

    // Mispair A's state with B's proof/refund.
    assert_eq!(
        prerefund_a
            .to_credit_token(&params, &proof_b, &refund_b, private_key.public())
            .err(),
        Some(Error::InvalidRefundProof)
    );
}

// ===== INTEGRATION =====

#[test]
fn test_full_lifecycle_with_mixed_operations() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let mut db = NullifierDb::new();
    let ctx = test_ctx();

    let mut token = issue_token(&params, &private_key, 1000, ctx);
    let mut expected: u128 = 1000;

    // (spend, topup, return) operations exercising the whole corridor:
    // plain spends, metered refunds, granted top-ups, a clawback, and a
    // pure top-up.
    let operations: [(u128, u128, u128); 6] = [
        (50, 0, 0),      // plain spend:            950
        (100, 0, 30),    // metered, return 30:     880
        (200, 500, 700), // grant top-up + cancel:  1380
        (600, 0, 100),   // metered, return 100:    880
        (100, 300, 0),   // clawback (payment failed): 780
        (0, 25, 25),     // pure top-up granted:    805
    ];

    for (s, a, t) in operations {
        let (spend_proof, prerefund) = token.prove_spend(&params, s, a, OsRng).unwrap();
        assert!(!db.is_spent(&spend_proof.nullifier()), "double spend");
        let refund = private_key.refund(&params, &spend_proof, t, OsRng).unwrap();
        db.record_spent(&spend_proof.nullifier());
        token = prerefund
            .to_credit_token(&params, &spend_proof, &refund, private_key.public())
            .unwrap();
        expected = expected - s + t;
        assert_eq!(token.credits(), Scalar::from(expected));
    }
    assert_eq!(expected, 805);
}

// ===== GENERIC DIGIT COUNTS =====

/// The protocol is generic over the digit count: run a full
/// issue/spend/settle round plus a wire round trip at several D values,
/// including both extremes of the safe range.
#[test]
fn test_generic_digit_counts() {
    fn corridor_round<const DD: usize>() {
        let params: Params<DD> = Params::new("gen-org", "gen-svc", "test", "2024-01-01");
        let private_key = PrivateKey::random(OsRng);
        let max = Params::<DD>::MAX_CREDITS;
        // A balance, spend, and top-up that fit any D >= 2.
        let c = 8u128.min(max / 2);
        let a = 8u128.min(max - c);
        let s = c / 2;
        let token = issue_token(&params, &private_key, c, test_ctx());
        // Settle at the ceiling endpoint of the corridor.
        let token = spend_round(&params, &private_key, &token, s, a, s + a).unwrap();
        assert_eq!(token.credits(), Scalar::from(c + a));
        // And a wire round trip at this D.
        let (spend_proof, _) = token.prove_spend(&params, 0, 0, OsRng).unwrap();
        let decoded = SpendProof::<DD>::from_bytes(&spend_proof.to_bytes()).unwrap();
        assert!(private_key.refund(&params, &decoded, 0, OsRng).is_ok());
    }
    corridor_round::<2>();
    corridor_round::<4>();
    corridor_round::<40>();
    corridor_round::<80>();
}

// ===== PROPERTY-BASED TESTS =====

/// Strategy for generating random Scalars
fn scalar_strategy() -> impl Strategy<Value = Scalar> {
    prop::array::uniform32(any::<u8>()).prop_map(Scalar::from_bytes_mod_order)
}

/// Strategy for generating valid RistrettoPoints
fn point_strategy() -> impl Strategy<Value = RistrettoPoint> {
    scalar_strategy().prop_map(|s| RistrettoPoint::generator() * s)
}

proptest! {
    #![proptest_config(fast_config())]

    /// Balances are conserved through spend/top-up/return rounds:
    /// final = c - s + t for any return amount t in [0, s + a].
    #[test]
    fn prop_balance_conservation(
        c in 0u128..=MAX_CREDITS / 2,
        s_frac in 0u128..=100,
        a in 0u128..=MAX_CREDITS / 2,
        t_frac in 0u128..=100,
    ) {
        let s = c * s_frac / 100;
        let t = (s + a) * t_frac / 100;

        let params = test_params();
        let private_key = PrivateKey::random(OsRng);
        let token = issue_token(&params, &private_key, c, test_ctx());
        let new_token = spend_round(&params, &private_key, &token, s, a, t).unwrap();
        prop_assert_eq!(new_token.credits(), Scalar::from(c - s + t));
    }

    /// Every point of the settlement corridor [c - s, c + a] is reachable:
    /// the issuer settles at any target f by returning t = f - (c - s).
    #[test]
    fn prop_corridor_reachability(
        c in 0u128..=MAX_CREDITS / 2,
        s_frac in 0u128..=100,
        a in 0u128..=MAX_CREDITS / 2,
        f_frac in 0u128..=100,
    ) {
        let s = c * s_frac / 100;
        // A settlement target anywhere in [c - s, c + a].
        let f = (c - s) + (s + a) * f_frac / 100;
        let t = f - (c - s);

        let params = test_params();
        let private_key = PrivateKey::random(OsRng);
        let token = issue_token(&params, &private_key, c, test_ctx());
        let new_token = spend_round(&params, &private_key, &token, s, a, t).unwrap();
        prop_assert_eq!(new_token.credits(), Scalar::from(f));
        // The reached balance is itself a valid credit amount.
        prop_assert!(f <= MAX_CREDITS);
    }

    /// Spending more than the balance always fails client-side, no matter
    /// the declared top-up: the floor proof needs s <= c.
    #[test]
    fn prop_overspend_always_fails(
        c in 0u128..=MAX_CREDITS / 2,
        a in 0u128..=MAX_CREDITS / 2,
        excess in 1u128..=MAX_CREDITS / 2,
    ) {
        let params = test_params();
        let private_key = PrivateKey::random(OsRng);
        let token = issue_token(&params, &private_key, c, test_ctx());
        prop_assert_eq!(
            token.prove_spend(&params, c + excess, a, OsRng).err(),
            Some(Error::InvalidAmount)
        );
    }

    /// A top-up that would lift the balance past the ceiling always fails
    /// client-side: the ceiling proof needs c + a < 3^D.
    #[test]
    fn prop_ceiling_always_enforced(
        c in 1u128..=MAX_CREDITS,
        s_frac in 0u128..=100,
        excess in 1u128..=MAX_CREDITS,
    ) {
        let a = MAX_CREDITS - c + excess; // c + a = MAX_CREDITS + excess
        prop_assume!(a <= MAX_CREDITS);
        let s = c * s_frac / 100;

        let params = test_params();
        let private_key = PrivateKey::random(OsRng);
        let token = issue_token(&params, &private_key, c, test_ctx());
        prop_assert_eq!(
            token.prove_spend(&params, s, a, OsRng).err(),
            Some(Error::InvalidAmount)
        );
    }

    /// Return amounts beyond s + a always fail issuer-side.
    #[test]
    fn prop_excess_refund_always_fails(
        c in 0u128..=MAX_CREDITS / 2,
        s_frac in 0u128..=100,
        a in 0u128..=MAX_CREDITS / 2,
        excess in 1u128..=MAX_CREDITS,
    ) {
        let params = test_params();
        let private_key = PrivateKey::random(OsRng);
        let s = c * s_frac / 100;
        let token = issue_token(&params, &private_key, c, test_ctx());
        let (spend_proof, _) = token.prove_spend(&params, s, a, OsRng).unwrap();
        let t = s + a + excess;
        prop_assert_eq!(
            private_key.refund(&params, &spend_proof, t, OsRng).err(),
            Some(Error::InvalidRefundAmount)
        );
    }

    /// A dishonest decomposition of either proven value is rejected: the
    /// consistency equations tie both digit vectors to the real balance, so
    /// either the prover cannot produce the proof or the issuer rejects it.
    #[test]
    fn prop_forged_decomposition_rejected(
        c in 1u128..=MAX_CREDITS / 2,
        s_frac in 1u128..=100,
        a in 0u128..=MAX_CREDITS / 2,
        delta in 1u128..=1000,
        forge_floor in any::<bool>(),
    ) {
        let params = test_params();
        let private_key = PrivateKey::random(OsRng);
        let s = 1 + (c - 1) * s_frac / 100;
        let token = issue_token(&params, &private_key, c, test_ctx());

        // Forge one decomposition to a wrong (in-range) value; keep the
        // other honest.
        let honest1 = c - s;
        let honest2 = c + a;
        let (v1, v2) = if forge_floor {
            ((honest1 + delta) % (MAX_CREDITS + 1), honest2)
        } else {
            (honest1, (honest2 + delta) % (MAX_CREDITS + 1))
        };
        prop_assume!(v1 != honest1 || v2 != honest2);
        let digits1 = trits_of(&Scalar::from(v1));
        let digits2 = trits_of(&Scalar::from(v2));

        let result = token.prove_spend_with_digits(
            &params,
            Scalar::from(s),
            Scalar::from(a),
            &digits1,
            &digits2,
            OsRng,
        );
        if let Ok((spend_proof, _)) = result {
            prop_assert_eq!(
                private_key.refund(&params, &spend_proof, 0, OsRng).err(),
                Some(Error::InvalidClientSpendProof)
            );
        }
    }

    /// A random multi-round chain conserves the balance under arbitrary
    /// valid (spend, top-up, return) choices, exercising refund-token
    /// chaining end to end.
    #[test]
    fn prop_random_chain_conserves_balance(
        c0 in 0u128..=MAX_CREDITS / 2,
        ops in prop::collection::vec(
            (0u128..=100, 0u128..=MAX_CREDITS / 8, 0u128..=100), 1..=4),
    ) {
        let params = test_params();
        let private_key = PrivateKey::random(OsRng);
        let mut db = NullifierDb::new();
        let mut token = issue_token(&params, &private_key, c0, test_ctx());
        let mut expected = c0;

        for (s_frac, a_raw, t_frac) in ops {
            let s = expected * s_frac / 100;
            let a = a_raw.min(MAX_CREDITS - expected);
            let t = (s + a) * t_frac / 100;

            let (spend_proof, prerefund) =
                token.prove_spend(&params, s, a, OsRng).unwrap();
            prop_assert!(!db.is_spent(&spend_proof.nullifier()));
            db.record_spent(&spend_proof.nullifier());
            let refund = private_key.refund(&params, &spend_proof, t, OsRng).unwrap();
            token = prerefund
                .to_credit_token(&params, &spend_proof, &refund, private_key.public())
                .unwrap();
            expected = expected - s + t;
            prop_assert_eq!(token.credits(), Scalar::from(expected));
        }
    }

    /// TritDecompose roundtrips over the full credit range.
    #[test]
    fn prop_trit_decompose_roundtrip(raw in any::<u128>()) {
        let v = raw % (MAX_CREDITS + 1);
        let digits = trits_of(&Scalar::from(v));
        prop_assert_eq!(recompose_trits(&digits), v);
    }

    /// Sequential spends accumulate correctly.
    #[test]
    fn prop_sequential_spends_accumulate(
        c in 100u128..=MAX_CREDITS,
        s1_frac in 0u128..=100,
        s2_frac in 0u128..=100,
    ) {
        let params = test_params();
        let private_key = PrivateKey::random(OsRng);
        let s1 = c * s1_frac / 100;
        let s2 = (c - s1) * s2_frac / 100;

        let token = issue_token(&params, &private_key, c, test_ctx());
        let token = spend_round(&params, &private_key, &token, s1, 0, 0).unwrap();
        let token = spend_round(&params, &private_key, &token, s2, 0, 0).unwrap();
        prop_assert_eq!(token.credits(), Scalar::from(c - s1 - s2));
    }

    /// Any single-byte corruption of the compact proof is rejected.
    #[test]
    fn prop_corrupted_pok_rejected(index_frac in 0usize..100, mask in 1u8..=255) {
        let params = test_params();
        let private_key = PrivateKey::random(OsRng);
        let token = issue_token(&params, &private_key, 100, test_ctx());
        let (mut spend_proof, _) = token.prove_spend(&params, 10, 0, OsRng).unwrap();
        let n = spend_proof.pok.len();
        spend_proof.pok[index_frac * (n - 1) / 99] ^= mask;
        prop_assert!(private_key.refund(&params, &spend_proof, 0, OsRng).is_err());
    }

    /// Wire-format roundtrip for real spend proofs.
    #[test]
    fn prop_wire_round_trip_spend_proof(
        c in 0u128..=MAX_CREDITS / 2,
        a in 0u128..=MAX_CREDITS / 2,
    ) {
        let params = test_params();
        let private_key = PrivateKey::random(OsRng);
        let token = issue_token(&params, &private_key, c, test_ctx());
        let (spend_proof, prerefund) = token.prove_spend(&params, c / 2, a, OsRng).unwrap();

        let bytes = spend_proof.to_bytes();
        let decoded = SpendProof::from_bytes(&bytes).unwrap();

        // The decoded proof still verifies and refunds correctly; the
        // issuer grants the declared top-up (t = a).
        let refund = private_key.refund(&params, &decoded, a, OsRng).unwrap();
        let new_token = prerefund
            .to_credit_token(&params, &decoded, &refund, private_key.public())
            .unwrap();
        prop_assert_eq!(new_token.credits(), Scalar::from(c - c / 2 + a));
    }

    /// Wire-format roundtrip for refunds produced by the issuer.
    #[test]
    fn prop_wire_round_trip_refund(t in 0u128..50) {
        let params = test_params();
        let private_key = PrivateKey::random(OsRng);
        let token = issue_token(&params, &private_key, 100, test_ctx());
        let (spend_proof, prerefund) = token.prove_spend(&params, 50, 0, OsRng).unwrap();
        let refund = private_key.refund(&params, &spend_proof, t, OsRng).unwrap();

        let bytes = refund.to_bytes();
        let decoded = Refund::from_bytes(&bytes).unwrap();
        let new_token = prerefund
            .to_credit_token(&params, &spend_proof, &decoded, private_key.public())
            .unwrap();
        prop_assert_eq!(new_token.credits(), Scalar::from(50 + t));
    }

    /// Wire-format roundtrip for credit tokens (including the context field).
    #[test]
    fn prop_wire_round_trip_credit_token(
        a in point_strategy(),
        e in scalar_strategy(),
        k in scalar_strategy(),
        r in scalar_strategy(),
        c in scalar_strategy(),
        ctx in scalar_strategy(),
    ) {
        let token = CreditToken { a, e, k, r, c, ctx };
        let bytes = token.to_bytes();
        let decoded = CreditToken::from_bytes(&bytes).unwrap();
        prop_assert_eq!(token, decoded);
    }

    /// Tokens issued under different parameters or keys do not cross-verify.
    #[test]
    fn prop_issuer_isolation(c in 1u128..=MAX_CREDITS) {
        let params1 = test_params();
        let params2: Params<D> = Params::new("other-org", "other-svc", "prod", "2024-01-01");
        let key1 = PrivateKey::random(OsRng);
        let key2 = PrivateKey::random(OsRng);

        let token = issue_token(&params1, &key1, c, test_ctx());
        let (spend_proof, _) = token.prove_spend(&params1, 1, 0, OsRng).unwrap();

        // Wrong key.
        prop_assert!(key2.refund(&params1, &spend_proof, 0, OsRng).is_err());
        // Wrong parameters.
        prop_assert!(key1.refund(&params2, &spend_proof, 0, OsRng).is_err());
    }
}
