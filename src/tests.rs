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

fn test_params() -> Params {
    Params::new("test-org", "test-service", "test-env", "2024-01-01")
}

fn test_ctx() -> Scalar {
    Scalar::from(20250710u64)
}

/// Runs the full issuance protocol and returns the resulting token.
fn issue_token(params: &Params, private_key: &PrivateKey, c: u128, ctx: Scalar) -> CreditToken {
    let pre_issuance = PreIssuance::random(OsRng);
    let request = pre_issuance.request(params, OsRng);
    let response = private_key.issue(params, &request, c, ctx, OsRng).unwrap();
    pre_issuance
        .to_credit_token(params, private_key.public(), &request, &response, ctx)
        .unwrap()
}

/// Runs one spend/refund round trip and returns the new token.
fn spend_round(
    params: &Params,
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
    let params1 = Params::new("org", "svc", "prod", "2024-01-01");
    let params2 = Params::new("org", "svc", "prod", "2024-01-01");
    assert_eq!(params1, params2);

    // Any change to the domain separator changes the parameters.
    let params3 = Params::new("org", "svc", "prod", "2024-01-02");
    assert_ne!(params1, params3);
    let params4 = Params::new("org", "svc", "staging", "2024-01-01");
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
    let params = Params::from_domain_separator(long.as_bytes());
    let params2 = Params::from_domain_separator(long.as_bytes());
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
    let digits = trits_of(&Scalar::from(MAX_CREDITS));
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

    // Spend 30 while topping up 50: new balance 120.
    let (spend_proof, prerefund) = token.prove_spend(&params, 30, 50, OsRng).unwrap();
    assert_eq!(spend_proof.charge(), Scalar::from(30u64));
    assert_eq!(spend_proof.topup(), Scalar::from(50u64));
    let refund = private_key.refund(&params, &spend_proof, 0, OsRng).unwrap();
    let token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();
    assert_eq!(token.credits(), Scalar::from(120u64));

    // The new token spends normally.
    let token = spend_round(&params, &private_key, &token, 120, 0, 0).unwrap();
    assert_eq!(token.credits(), Scalar::ZERO);
}

#[test]
fn test_topup_covers_spend_beyond_balance() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let token = issue_token(&params, &private_key, 10, test_ctx());

    // s may exceed the balance when the top-up covers the difference:
    // v = 10 - 200 + 300 = 110.
    let token = spend_round(&params, &private_key, &token, 200, 300, 0).unwrap();
    assert_eq!(token.credits(), Scalar::from(110u64));
}

#[test]
fn test_topup_insufficient_balance_rejected() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let token = issue_token(&params, &private_key, 10, test_ctx());

    // v = 10 - 200 + 100 < 0: rejected client-side.
    assert_eq!(
        token.prove_spend(&params, 200, 100, OsRng).err(),
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
fn test_refund_bound_accounts_for_topup() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let token = issue_token(&params, &private_key, 100, test_ctx());

    // With s = 50 and a = 20, the partial refund is bounded by s - a = 30.
    let (spend_proof, prerefund) = token.prove_spend(&params, 50, 20, OsRng).unwrap();
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
    // 100 - 50 + 20 + 30 = 100.
    assert_eq!(token.credits(), Scalar::from(100u64));

    // With a > s, no partial refund is allowed at all.
    let (spend_proof, _) = token.prove_spend(&params, 50, 60, OsRng).unwrap();
    assert_eq!(
        private_key.refund(&params, &spend_proof, 1, OsRng).err(),
        Some(Error::InvalidRefundAmount)
    );
    assert!(private_key.refund(&params, &spend_proof, 0, OsRng).is_ok());
}

// ===== AMOUNT VALIDATION AND WRAPAROUND =====

/// A malicious client crafts a spend whose public amount wraps around the
/// group order: with balance c and claimed remainder v, the scalar relation
/// v = c - s + a (mod q) holds for s = c - v mod q even when v is enormous.
/// The sigma protocol proof VERIFIES (the relation is true in the scalar
/// field); only the issuer's integer validation of s blocks the attack.
#[test]
fn test_wraparound_attack_is_blocked_by_amount_validation() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let token = issue_token(&params, &private_key, 5, test_ctx());

    // Claim the maximum possible remainder.
    let v_target = MAX_CREDITS;
    let digits = trits_of(&Scalar::from(v_target));
    // s = c - v mod q: a "spend" that inflates the balance to v_target.
    let s_scalar = Scalar::from(5u64) - Scalar::from(v_target);
    let (spend_proof, _prerefund) = token
        .prove_spend_with_digits(&params, s_scalar, Scalar::ZERO, &digits, OsRng)
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
        &spend_proof.com,
        &spend_proof.t,
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
/// group order (here a = -1 mod q, a "negative top-up" that silently drains
/// one credit) satisfies the scalar relation but must be rejected by the
/// issuer's integer validation of a.
#[test]
fn test_wraparound_topup_is_blocked_by_amount_validation() {
    let params = test_params();
    let private_key = PrivateKey::random(OsRng);
    let token = issue_token(&params, &private_key, 5, test_ctx());

    // With s = 0 and a = -1 mod q, the claimed remainder v = 5 - 1 = 4
    // satisfies v = c - s + a in the scalar field.
    let digits = trits_of(&Scalar::from(4u64));
    let a_scalar = Scalar::ZERO - Scalar::ONE;
    let (spend_proof, _) = token
        .prove_spend_with_digits(&params, Scalar::ZERO, a_scalar, &digits, OsRng)
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

    // Shift (s, a) -> (s + 5, a + 5): v is unchanged, and both remain valid
    // credit amounts, but the proof was bound to the original s and a.
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

    // Represent the remainder 3 as a single digit of value 3 instead of
    // the honest [0, 1, 0, ...]. The consistency equation still balances,
    // so only the ternary constraint can catch this.
    let mut digits = [Scalar::ZERO; D];
    digits[0] = Scalar::from(3u64);

    // The proving backend may refuse to prove the false statement outright;
    // if it produced a proof, the issuer must reject it.
    if let Ok((spend_proof, _)) =
        token.prove_spend_with_digits(&params, Scalar::ZERO, Scalar::ZERO, &digits, OsRng)
    {
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
        p.com[D - 1] += RistrettoPoint::generator();
        assert!(private_key.refund(&params, &p, 0, OsRng).is_err());
    }
    {
        let mut p = spend_proof.clone();
        p.t[D / 2] += RistrettoPoint::generator();
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

    // (spend, topup, refund) operations.
    let operations: [(u128, u128, u128); 5] = [
        (50, 0, 0),
        (100, 0, 30),
        (200, 500, 0),
        (600, 0, 100),
        (0, 25, 0),
    ];

    for (s, a, t) in operations {
        let (spend_proof, prerefund) = token.prove_spend(&params, s, a, OsRng).unwrap();
        assert!(!db.is_spent(&spend_proof.nullifier()), "double spend");
        let refund = private_key.refund(&params, &spend_proof, t, OsRng).unwrap();
        db.record_spent(&spend_proof.nullifier());
        token = prerefund
            .to_credit_token(&params, &spend_proof, &refund, private_key.public())
            .unwrap();
        expected = expected - s + a + t;
        assert_eq!(token.credits(), Scalar::from(expected));
    }
    assert_eq!(expected, 1000 - 50 - 70 + 300 - 500 + 25);
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

    /// Balances are conserved through spend/top-up/refund rounds:
    /// final = c - s + a + t.
    #[test]
    fn prop_balance_conservation(
        c in 0u128..=MAX_CREDITS / 2,
        s in 0u128..=MAX_CREDITS,
        a in 0u128..=MAX_CREDITS / 2,
        t_frac in 0u128..=100,
    ) {
        prop_assume!(c + a >= s);
        let t = (s.saturating_sub(a)) * t_frac / 100;

        let params = test_params();
        let private_key = PrivateKey::random(OsRng);
        let token = issue_token(&params, &private_key, c, test_ctx());
        let new_token = spend_round(&params, &private_key, &token, s, a, t).unwrap();
        prop_assert_eq!(new_token.credits(), Scalar::from(c + a + t - s));
    }

    /// Spending more than c + a always fails client-side.
    #[test]
    fn prop_overspend_always_fails(
        c in 0u128..=MAX_CREDITS / 2,
        a in 0u128..=MAX_CREDITS / 2,
        excess in 1u128..=MAX_CREDITS,
    ) {
        let params = test_params();
        let private_key = PrivateKey::random(OsRng);
        let token = issue_token(&params, &private_key, c, test_ctx());
        prop_assert_eq!(
            token.prove_spend(&params, c + a + excess, a, OsRng).err(),
            Some(Error::InvalidAmount)
        );
    }

    /// Partial refunds beyond max(0, s - a) always fail issuer-side.
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
        let t = s.saturating_sub(a) + excess;
        prop_assert_eq!(
            private_key.refund(&params, &spend_proof, t, OsRng).err(),
            Some(Error::InvalidRefundAmount)
        );
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

        // The decoded proof still verifies and refunds correctly.
        let refund = private_key.refund(&params, &decoded, 0, OsRng).unwrap();
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
        let params2 = Params::new("other-org", "other-svc", "prod", "2024-01-01");
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
