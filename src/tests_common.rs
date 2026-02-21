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

//! Generic test functions for the Anonymous Credit Token protocol.
//!
//! Each test is written as a generic `pub(crate) fn test_*<C: TestCiphersuite>()`
//! function. The [`instantiate_tests`] macro stamps out concrete `#[test]` items
//! for a given ciphersuite type.

#![cfg(test)]

use group::ff::Field;
use group::Group;
use rand::{Rng, thread_rng};
use rand_core::OsRng;
use std::collections::HashSet;

use crate::ciphersuite::{Ciphersuite, ErrorCode};
use crate::protocol::{
    credit_to_scalar, CreditToken, IssuanceRequest, IssuanceResponse, Params, PreIssuance,
    PrivateKey, Refund, SpendProof,
};
use crate::transcript::Transcript;

// ── TestCiphersuite trait ──────────────────────────────────────────────

/// Extension trait that provides a deterministic test context for each ciphersuite.
pub(crate) trait TestCiphersuite: Ciphersuite {
    /// Returns a deterministic, nonzero scalar derived from a fixed label.
    fn test_context() -> Self::Scalar;
}

// ── NullifierDb ────────────────────────────────────────────────────────

/// A simple in-memory nullifier database for testing double-spend prevention.
pub(crate) struct NullifierDb {
    pub(crate) used_nullifiers: HashSet<Vec<u8>>,
}

impl NullifierDb {
    pub(crate) fn new() -> Self {
        Self {
            used_nullifiers: HashSet::new(),
        }
    }

    pub(crate) fn is_spent<C: Ciphersuite>(&self, nullifier: &C::Scalar) -> bool {
        self.used_nullifiers.contains(C::scalar_to_bytes(nullifier).as_ref())
    }

    pub(crate) fn record_spent<C: Ciphersuite>(&mut self, nullifier: &C::Scalar) {
        self.used_nullifiers.insert(C::scalar_to_bytes(nullifier).as_ref().to_vec());
    }
}

// ── Helper functions ───────────────────────────────────────────────────

/// Issue a token with `c` credits using the given params and key.
pub(crate) fn issue_token<C: TestCiphersuite>(
    params: &Params<C>,
    private_key: &PrivateKey<C>,
    c: u128,
) -> CreditToken<C> {
    let preissuance = PreIssuance::random(OsRng);
    let request = preissuance.request(params, OsRng);
    let response = private_key
        .issue::<128>(params, &request, C::scalar_from_u128(c), C::test_context(), OsRng)
        .unwrap();
    preissuance
        .to_credit_token::<128>(params, private_key.public(), &request, &response)
        .unwrap()
}

/// Spend `s` credits from a token with partial return `t`, returning the new token.
pub(crate) fn spend_with_return<C: TestCiphersuite>(
    params: &Params<C>,
    private_key: &PrivateKey<C>,
    token: &CreditToken<C>,
    s: u128,
    t: u128,
) -> CreditToken<C> {
    let (spend_proof, prerefund) = token
        .prove_spend::<128>(params, C::scalar_from_u128(s), OsRng)
        .unwrap();
    let refund = private_key
        .refund(params, &spend_proof, C::scalar_from_u128(t), OsRng)
        .unwrap();
    prerefund
        .to_credit_token(params, &spend_proof, &refund, private_key.public())
        .unwrap()
}

// ── Generic test functions ─────────────────────────────────────────────

pub(crate) fn test_issuance<C: TestCiphersuite>() {
    for _i in 0..100 {
        let private_key = PrivateKey::<C>::random(OsRng);
        let preissuance = PreIssuance::<C>::random(OsRng);
        let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
        let issuance_request = preissuance.request(&params, OsRng);

        // Random credit amount between 1 and 1000
        let credit_amount = C::scalar_from_u128(thread_rng().gen_range(1u128..1000));

        let issuance_response = private_key
            .issue::<128>(
                &params,
                &issuance_request,
                credit_amount,
                C::test_context(),
                OsRng,
            )
            .unwrap();
        let _credit_token = preissuance
            .to_credit_token::<128>(
                &params,
                private_key.public(),
                &issuance_request,
                &issuance_response,
            )
            .unwrap();
    }
}

pub(crate) fn test_full_cycle<C: TestCiphersuite>() {
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    for _i in 0..10 {
        let private_key = PrivateKey::<C>::random(OsRng);
        let preissuance = PreIssuance::<C>::random(OsRng);
        let issuance_request = preissuance.request(&params, OsRng);

        // Random credit amount between 100 and 2000
        let total_credits = thread_rng().gen_range(100u128..2000);
        let credit_amount = C::scalar_from_u128(total_credits);

        let issuance_response = private_key
            .issue::<128>(
                &params,
                &issuance_request,
                credit_amount,
                C::test_context(),
                OsRng,
            )
            .unwrap();
        let credit_token1 = preissuance
            .to_credit_token::<128>(
                &params,
                private_key.public(),
                &issuance_request,
                &issuance_response,
            )
            .unwrap();

        // First charge: random amount between 1 and 1/2 of total credits
        let first_charge = thread_rng().gen_range(1u128..=(total_credits / 2));
        let charge1 = C::scalar_from_u128(first_charge);

        let (spend_proof, prerefund) = credit_token1
            .prove_spend::<128>(&params, charge1, OsRng)
            .unwrap();
        let refund = private_key
            .refund(
                &params,
                &spend_proof,
                <C::Scalar as Field>::ZERO,
                OsRng,
            )
            .unwrap();
        let credit_token2 = prerefund
            .to_credit_token(&params, &spend_proof, &refund, private_key.public())
            .unwrap();

        // Second charge: remaining credits
        let remaining_credits = total_credits - first_charge;
        let charge2 = C::scalar_from_u128(remaining_credits);

        let (spend_proof, prerefund) = credit_token2
            .prove_spend::<128>(&params, charge2, OsRng)
            .unwrap();
        let refund = private_key
            .refund(
                &params,
                &spend_proof,
                <C::Scalar as Field>::ZERO,
                OsRng,
            )
            .unwrap();
        let _credit_token3 = prerefund
            .to_credit_token(&params, &spend_proof, &refund, private_key.public())
            .unwrap();
    }
}

pub(crate) fn test_double_spend_prevention<C: TestCiphersuite>() {
    // Initialize nullifier database
    let mut nullifier_db = NullifierDb::new();

    // Setup issuer and client
    let private_key = PrivateKey::<C>::random(OsRng);
    let preissuance = PreIssuance::<C>::random(OsRng);
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let issuance_request = preissuance.request(&params, OsRng);

    // Random credit amount between 100 and 1000
    let total_credits = thread_rng().gen_range(100u128..1000);
    let credit_amount = C::scalar_from_u128(total_credits);

    let issuance_response = private_key
        .issue::<128>(
            &params,
            &issuance_request,
            credit_amount,
            C::test_context(),
            OsRng,
        )
        .unwrap();
    let credit_token = preissuance
        .to_credit_token::<128>(
            &params,
            private_key.public(),
            &issuance_request,
            &issuance_response,
        )
        .unwrap();

    // First spend is successful - random amount between 1 and 1/3 of total credits
    let first_charge = thread_rng().gen_range(1u128..=(total_credits / 3));
    let charge1 = C::scalar_from_u128(first_charge);

    let (spend_proof1, prerefund1) = credit_token
        .prove_spend::<128>(&params, charge1, OsRng)
        .unwrap();

    // Verify nullifier isn't already spent
    let nullifier = spend_proof1.nullifier();
    assert!(
        !nullifier_db.is_spent::<C>(&nullifier),
        "Nullifier should not be spent yet"
    );

    // Process refund
    let refund1 = private_key
        .refund(
            &params,
            &spend_proof1,
            <C::Scalar as Field>::ZERO,
            OsRng,
        )
        .unwrap();

    // Record nullifier as spent
    nullifier_db.record_spent::<C>(&nullifier);

    // Create new token from refund
    let new_token = prerefund1
        .to_credit_token(&params, &spend_proof1, &refund1, private_key.public())
        .unwrap();

    // Attempt to use the same original token (double-spend attempt)
    let second_charge = thread_rng().gen_range(1u128..=(total_credits / 2));
    let charge2 = C::scalar_from_u128(second_charge);

    let (spend_proof2, _) = credit_token
        .prove_spend::<128>(&params, charge2, OsRng)
        .unwrap();

    // Check nullifier - should detect double spend
    let nullifier2 = spend_proof2.nullifier();
    assert!(
        nullifier_db.is_spent::<C>(&nullifier2),
        "Double-spend not detected"
    );

    // Verify we can spend from the new token
    let remaining_credits = total_credits - first_charge;
    let third_charge = thread_rng().gen_range(1u128..remaining_credits);
    let charge3 = C::scalar_from_u128(third_charge);

    let (spend_proof3, _) = new_token
        .prove_spend::<128>(&params, charge3, OsRng)
        .unwrap();
    let nullifier3 = spend_proof3.nullifier();

    // This is a different nullifier, should not be detected as spent
    assert!(
        !nullifier_db.is_spent::<C>(&nullifier3),
        "New token spend incorrectly marked as double-spend"
    );
}

pub(crate) fn test_spend_exact_balance<C: TestCiphersuite>() {
    // Test spending the exact balance amount
    let private_key = PrivateKey::<C>::random(OsRng);
    let preissuance = PreIssuance::<C>::random(OsRng);
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let issuance_request = preissuance.request(&params, OsRng);

    // Random credit amount between 10 and 1000
    let total_credits = thread_rng().gen_range(10u128..1000);
    let credit_amount = C::scalar_from_u128(total_credits);

    let issuance_response = private_key
        .issue::<128>(
            &params,
            &issuance_request,
            credit_amount,
            C::test_context(),
            OsRng,
        )
        .unwrap();
    let credit_token = preissuance
        .to_credit_token::<128>(
            &params,
            private_key.public(),
            &issuance_request,
            &issuance_response,
        )
        .unwrap();

    // Spend the exact balance amount
    let (spend_proof, prerefund) = credit_token
        .prove_spend::<128>(&params, credit_amount, OsRng)
        .unwrap();

    // Verify the refund amount is zero
    assert_eq!(
        prerefund.m,
        <C::Scalar as Field>::ZERO,
        "Remaining balance should be zero"
    );

    // Verify the refund still processes correctly
    let refund = private_key
        .refund(
            &params,
            &spend_proof,
            <C::Scalar as Field>::ZERO,
            OsRng,
        )
        .unwrap();
    let new_token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();

    // New token should have zero balance
    assert_eq!(
        new_token.c,
        <C::Scalar as Field>::ZERO,
        "New token should have zero balance"
    );
}

pub(crate) fn test_sequential_spends<C: TestCiphersuite>() {
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let private_key = PrivateKey::<C>::random(OsRng);

    // Issue 1000 credits
    let token = issue_token::<C>(&params, &private_key, 1000);

    // Spend 200
    let (spend_proof, prerefund) = token
        .prove_spend::<128>(&params, C::scalar_from_u128(200), OsRng)
        .unwrap();
    assert_eq!(prerefund.m, C::scalar_from_u128(800));

    let refund = private_key
        .refund(
            &params,
            &spend_proof,
            <C::Scalar as Field>::ZERO,
            OsRng,
        )
        .unwrap();
    let token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();
    assert_eq!(token.c, C::scalar_from_u128(800));

    // Spend 300
    let (spend_proof, prerefund) = token
        .prove_spend::<128>(&params, C::scalar_from_u128(300), OsRng)
        .unwrap();
    assert_eq!(prerefund.m, C::scalar_from_u128(500));

    let refund = private_key
        .refund(
            &params,
            &spend_proof,
            <C::Scalar as Field>::ZERO,
            OsRng,
        )
        .unwrap();
    let token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();
    assert_eq!(token.c, C::scalar_from_u128(500));
}

pub(crate) fn test_attempt_overspend<C: TestCiphersuite>() {
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let private_key = PrivateKey::<C>::random(OsRng);

    // Issue 500 credits
    let token = issue_token::<C>(&params, &private_key, 500);

    // Try to spend 501
    let result = token.prove_spend::<128>(&params, C::scalar_from_u128(501), OsRng);
    assert!(
        result.is_err(),
        "Overspend should have been rejected by prove_spend"
    );
}

pub(crate) fn test_zero_spend_scenario<C: TestCiphersuite>() {
    let private_key = PrivateKey::<C>::random(OsRng);
    let preissuance = PreIssuance::<C>::random(OsRng);
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let issuance_request = preissuance.request(&params, OsRng);

    let credit_value = thread_rng().gen_range(10u128..1000);
    let credit_amount = C::scalar_from_u128(credit_value);

    let issuance_response = private_key
        .issue::<128>(
            &params,
            &issuance_request,
            credit_amount,
            C::test_context(),
            OsRng,
        )
        .unwrap();
    let credit_token = preissuance
        .to_credit_token::<128>(
            &params,
            private_key.public(),
            &issuance_request,
            &issuance_response,
        )
        .unwrap();

    // Spend zero credits (re-anonymize)
    let zero_spend = <C::Scalar as Field>::ZERO;
    let (spend_proof, prerefund) = credit_token
        .prove_spend::<128>(&params, zero_spend, OsRng)
        .unwrap();

    let refund = private_key
        .refund(
            &params,
            &spend_proof,
            <C::Scalar as Field>::ZERO,
            OsRng,
        )
        .unwrap();

    // Remaining balance should still be the original amount
    assert_eq!(
        prerefund.m, credit_amount,
        "Remaining balance should be unchanged"
    );

    // Create new token
    let new_token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();

    // New token should have the same balance
    assert_eq!(
        new_token.c, credit_amount,
        "New token should have the original amount"
    );
}

pub(crate) fn test_multiple_tokens_with_same_issuer<C: TestCiphersuite>() {
    let mut nullifier_db = NullifierDb::new();

    // Single issuer
    let private_key = PrivateKey::<C>::random(OsRng);
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();

    // First token
    let credit_value1 = thread_rng().gen_range(50u128..500);
    let credit_amount1 = C::scalar_from_u128(credit_value1);

    let preissuance1 = PreIssuance::<C>::random(OsRng);
    let request1 = preissuance1.request(&params, OsRng);
    let response1 = private_key
        .issue::<128>(&params, &request1, credit_amount1, C::test_context(), OsRng)
        .unwrap();
    let token1 = preissuance1
        .to_credit_token::<128>(&params, private_key.public(), &request1, &response1)
        .unwrap();

    // Second token
    let credit_value2 = thread_rng().gen_range(30u128..300);
    let credit_amount2 = C::scalar_from_u128(credit_value2);

    let preissuance2 = PreIssuance::<C>::random(OsRng);
    let request2 = preissuance2.request(&params, OsRng);
    let response2 = private_key
        .issue::<128>(&params, &request2, credit_amount2, C::test_context(), OsRng)
        .unwrap();
    let token2 = preissuance2
        .to_credit_token::<128>(&params, private_key.public(), &request2, &response2)
        .unwrap();

    // Both clients spend
    let spend_value1 = thread_rng().gen_range(1u128..=(credit_value1 / 2));
    let spend_amount1 = C::scalar_from_u128(spend_value1);
    let expected_remaining1 = credit_value1 - spend_value1;

    let spend_value2 = thread_rng().gen_range(1u128..=(credit_value2 / 2));
    let spend_amount2 = C::scalar_from_u128(spend_value2);
    let expected_remaining2 = credit_value2 - spend_value2;

    let (spend_proof1, prerefund1) = token1
        .prove_spend::<128>(&params, spend_amount1, OsRng)
        .unwrap();
    let (spend_proof2, prerefund2) = token2
        .prove_spend::<128>(&params, spend_amount2, OsRng)
        .unwrap();

    // Nullifiers should be different
    let nullifier1 = spend_proof1.nullifier();
    let nullifier2 = spend_proof2.nullifier();
    assert_ne!(nullifier1, nullifier2, "Tokens should have different nullifiers");

    // Record both spends
    nullifier_db.record_spent::<C>(&nullifier1);
    nullifier_db.record_spent::<C>(&nullifier2);

    // Process refunds
    let refund1 = private_key
        .refund(
            &params,
            &spend_proof1,
            <C::Scalar as Field>::ZERO,
            OsRng,
        )
        .unwrap();
    let refund2 = private_key
        .refund(
            &params,
            &spend_proof2,
            <C::Scalar as Field>::ZERO,
            OsRng,
        )
        .unwrap();

    let new_token1 = prerefund1
        .to_credit_token(&params, &spend_proof1, &refund1, private_key.public())
        .unwrap();
    let new_token2 = prerefund2
        .to_credit_token(&params, &spend_proof2, &refund2, private_key.public())
        .unwrap();

    assert_eq!(
        new_token1.c,
        C::scalar_from_u128(expected_remaining1),
        "First token should have {} credits remaining",
        expected_remaining1
    );
    assert_eq!(
        new_token2.c,
        C::scalar_from_u128(expected_remaining2),
        "Second token should have {} credits remaining",
        expected_remaining2
    );
}

pub(crate) fn test_bits_of<C: TestCiphersuite>() {
    let x = C::scalar_from_u128(u128::MAX);
    let bits = C::bits_of::<128>(x);
    bits.iter().for_each(|bit| assert!(bool::from(*bit)));

    let x = <C::Scalar as Field>::ZERO;
    let bits = C::bits_of::<128>(x);
    bits.iter().for_each(|bit| assert!(!bool::from(*bit)));

    let x = C::scalar_from_u128(0b001);
    let bits = C::bits_of::<128>(x);
    bits.iter().enumerate().for_each(|(i, bit)| {
        let expected = i == 0;
        assert_eq!(bool::from(*bit), expected);
    });

    let x = C::scalar_from_u128(0b100000000);
    let bits = C::bits_of::<128>(x);
    bits.iter().enumerate().for_each(|(i, bit)| {
        let expected = i == 8;
        assert_eq!(bool::from(*bit), expected);
    });

    let x = C::scalar_from_u128(7);
    let bits = C::bits_of::<128>(x);
    bits.iter().enumerate().for_each(|(i, bit)| {
        let expected = i <= 2;
        assert_eq!(bool::from(*bit), expected);
    });

    let x = C::scalar_from_u128(
        0b10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010u128,
    );
    let bits = C::bits_of::<128>(x);
    bits.iter().enumerate().for_each(|(i, bit)| {
        let expected = i % 2 == 1;
        assert_eq!(bool::from(*bit), expected);
    });

    let x = C::scalar_from_u128(
        0b01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101u128,
    );
    let bits = C::bits_of::<128>(x);
    bits.iter().enumerate().for_each(|(i, bit)| {
        let expected = i % 2 == 0;
        assert_eq!(bool::from(*bit), expected);
    });
}

pub(crate) fn test_invalid_issuance_request<C: TestCiphersuite>() {
    let private_key = PrivateKey::<C>::random(OsRng);
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let preissuance = PreIssuance::<C>::random(OsRng);
    let valid_request = preissuance.request(&params, OsRng);

    // Tamper with the request by modifying the k_bar value
    let tampered_request = IssuanceRequest {
        big_k: valid_request.big_k,
        gamma: valid_request.gamma,
        k_bar: valid_request.k_bar + <C::Scalar as Field>::ONE,
        r_bar: valid_request.r_bar,
    };

    let issuance_response = private_key.issue::<128>(
        &params,
        &tampered_request,
        C::scalar_from_u128(20),
        C::test_context(),
        OsRng,
    );
    assert!(
        issuance_response.is_err(),
        "Tampered request should be rejected"
    );

    // The original request should be accepted
    let issuance_response = private_key.issue::<128>(
        &params,
        &valid_request,
        C::scalar_from_u128(20),
        C::test_context(),
        OsRng,
    );
    assert!(
        issuance_response.is_ok(),
        "Valid request should be accepted"
    );
}

pub(crate) fn test_invalid_proof_verification<C: TestCiphersuite>() {
    let private_key = PrivateKey::<C>::random(OsRng);
    let preissuance = PreIssuance::<C>::random(OsRng);
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let request = preissuance.request(&params, OsRng);

    let credit_value = thread_rng().gen_range(50u128..500);
    let credit_amount = C::scalar_from_u128(credit_value);

    let response = private_key
        .issue::<128>(&params, &request, credit_amount, C::test_context(), OsRng)
        .unwrap();
    let token = preissuance
        .to_credit_token::<128>(&params, private_key.public(), &request, &response)
        .unwrap();

    let spend_value = thread_rng().gen_range(10u128..credit_value / 2);
    let spend_amount = C::scalar_from_u128(spend_value);
    let (spend_proof, _) = token
        .prove_spend::<128>(&params, spend_amount, OsRng)
        .unwrap();

    // Tamper with the proof by modifying the amount
    let tampered_value = spend_value + thread_rng().gen_range(1u128..10);
    let tampered_proof = SpendProof {
        s: C::scalar_from_u128(tampered_value),
        ..spend_proof
    };

    let refund_result = private_key.refund(
        &params,
        &tampered_proof,
        <C::Scalar as Field>::ZERO,
        OsRng,
    );
    assert!(refund_result.is_err(), "Tampered proof should be rejected");
}

pub(crate) fn test_large_amount_issuance<C: TestCiphersuite>() {
    let private_key = PrivateKey::<C>::random(OsRng);
    let preissuance = PreIssuance::<C>::random(OsRng);
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let request = preissuance.request(&params, OsRng);

    // Use a large amount near 2^126
    let base_amount = 2u128.pow(128 - 2); // 2^126
    let variation = thread_rng().gen_range(0..base_amount);
    let large_amount_u128 = base_amount + variation;
    let large_amount = C::scalar_from_u128(large_amount_u128);

    let response = private_key
        .issue::<128>(&params, &request, large_amount, C::test_context(), OsRng)
        .unwrap();
    let token = preissuance
        .to_credit_token::<128>(&params, private_key.public(), &request, &response)
        .unwrap();

    // Spend a small portion
    let max_spend = std::cmp::min(base_amount / 2, 5_000_000);
    let spend_value = thread_rng().gen_range(1u128..max_spend);
    let spend_amount = C::scalar_from_u128(spend_value);

    let (spend_proof, prerefund) = token
        .prove_spend::<128>(&params, spend_amount, OsRng)
        .unwrap();

    let expected_remaining = large_amount - spend_amount;
    assert_eq!(
        prerefund.m, expected_remaining,
        "Remaining balance incorrect"
    );

    let refund = private_key
        .refund(
            &params,
            &spend_proof,
            <C::Scalar as Field>::ZERO,
            OsRng,
        )
        .unwrap();
    let new_token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();

    assert_eq!(
        new_token.c, expected_remaining,
        "New token balance incorrect"
    );
}

pub(crate) fn test_invalid_token_verification<C: TestCiphersuite>() {
    let private_key = PrivateKey::<C>::random(OsRng);
    let preissuance = PreIssuance::<C>::random(OsRng);
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let request = preissuance.request(&params, OsRng);
    let response = private_key
        .issue::<128>(
            &params,
            &request,
            C::scalar_from_u128(50),
            C::test_context(),
            OsRng,
        )
        .unwrap();

    // Tamper with the response
    let tampered_response = IssuanceResponse {
        gamma: response.gamma,
        a: response.a,
        e: response.e + <C::Scalar as Field>::ONE,
        z: response.z,
        c: response.c,
        ctx: response.ctx,
    };

    let token_result = preissuance.to_credit_token::<128>(
        &params,
        private_key.public(),
        &request,
        &tampered_response,
    );
    assert!(
        token_result.is_err(),
        "Tampered response should be rejected"
    );

    // The original response should be accepted
    let token_result =
        preissuance.to_credit_token::<128>(&params, private_key.public(), &request, &response);
    assert!(token_result.is_ok(), "Valid response should be accepted");
}

pub(crate) fn test_transcript_add_elements<C: TestCiphersuite>() {
    // Create points to add to the transcript
    let one = <C::Scalar as Field>::ONE;
    let point1 = C::generator_mul(&one);
    let point2 = C::generator_mul(&C::scalar_from_u128(2));
    let point3 = C::generator_mul(&C::scalar_from_u128(3));

    let params = Params::<C>::random(OsRng);

    // Create a transcript and add elements using add_elements
    let mut transcript1 = Transcript::<C>::new(&params.transcript_base, b"test");
    transcript1.add_elements([&point1, &point2, &point3].into_iter());
    let challenge1 = transcript1.challenge();

    // Create another transcript and add the same elements one by one
    let mut transcript2 = Transcript::<C>::new(&params.transcript_base, b"test");
    transcript2.add_element(&point1);
    transcript2.add_element(&point2);
    transcript2.add_element(&point3);
    let challenge2 = transcript2.challenge();

    assert_eq!(
        challenge1, challenge2,
        "add_elements should produce the same result as multiple add_element calls"
    );
}

pub(crate) fn test_tampered_refund_verification<C: TestCiphersuite>() {
    let private_key = PrivateKey::<C>::random(OsRng);
    let preissuance = PreIssuance::<C>::random(OsRng);
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let request = preissuance.request(&params, OsRng);
    let response = private_key
        .issue::<128>(
            &params,
            &request,
            C::scalar_from_u128(50),
            C::test_context(),
            OsRng,
        )
        .unwrap();
    let token = preissuance
        .to_credit_token::<128>(&params, private_key.public(), &request, &response)
        .unwrap();

    let spend_amount = C::scalar_from_u128(20);
    let (spend_proof, prerefund) = token
        .prove_spend::<128>(&params, spend_amount, OsRng)
        .unwrap();

    let refund = private_key
        .refund(
            &params,
            &spend_proof,
            <C::Scalar as Field>::ZERO,
            OsRng,
        )
        .unwrap();

    // Tamper with the refund
    let tampered_refund = Refund {
        a: refund.a,
        e: refund.e + <C::Scalar as Field>::ONE,
        gamma: refund.gamma,
        z: refund.z,
        t: refund.t,
    };

    let new_token_result = prerefund.to_credit_token(
        &params,
        &spend_proof,
        &tampered_refund,
        private_key.public(),
    );
    assert!(
        new_token_result.is_err(),
        "Tampered refund should be rejected"
    );

    // The original refund should be accepted
    let new_token_result =
        prerefund.to_credit_token(&params, &spend_proof, &refund, private_key.public());
    assert!(new_token_result.is_ok(), "Valid refund should be accepted");
}

pub(crate) fn test_zero_e_signature_attack<C: TestCiphersuite>() {
    let private_key = PrivateKey::<C>::random(OsRng);
    let preissuance = PreIssuance::<C>::random(OsRng);
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let request = preissuance.request(&params, OsRng);
    let response = private_key
        .issue::<128>(
            &params,
            &request,
            C::scalar_from_u128(20),
            C::test_context(),
            OsRng,
        )
        .unwrap();

    // Create a tampered response with e = 0
    let tampered_response = IssuanceResponse {
        a: response.a,
        e: <C::Scalar as Field>::ZERO,
        gamma: response.gamma,
        z: response.z,
        c: response.c,
        ctx: response.ctx,
    };

    let token_result = preissuance.to_credit_token::<128>(
        &params,
        private_key.public(),
        &request,
        &tampered_response,
    );
    assert!(token_result.is_err(), "Zero e value should be rejected");
}

pub(crate) fn test_spend_with_identity_a_prime<C: TestCiphersuite>() {
    let private_key = PrivateKey::<C>::random(OsRng);
    let preissuance = PreIssuance::<C>::random(OsRng);
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let request = preissuance.request(&params, OsRng);
    let response = private_key
        .issue::<128>(
            &params,
            &request,
            C::scalar_from_u128(20),
            C::test_context(),
            OsRng,
        )
        .unwrap();
    let token = preissuance
        .to_credit_token::<128>(&params, private_key.public(), &request, &response)
        .unwrap();

    // Create a valid spend proof
    let (mut spend_proof, _) = token
        .prove_spend::<128>(&params, C::scalar_from_u128(10), OsRng)
        .unwrap();

    // Tamper with the proof - set a_prime to identity
    spend_proof.a_prime = C::Point::identity();

    let refund_result = private_key.refund(
        &params,
        &spend_proof,
        <C::Scalar as Field>::ZERO,
        OsRng,
    );
    assert!(
        refund_result.is_err(),
        "Spend proof with identity a_prime should be rejected"
    );
}

pub(crate) fn test_issuance_rejects_zero_credits<C: TestCiphersuite>() {
    let private_key = PrivateKey::<C>::random(OsRng);
    let preissuance = PreIssuance::<C>::random(OsRng);
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let request = preissuance.request(&params, OsRng);
    let response = private_key.issue::<128>(
        &params,
        &request,
        <C::Scalar as Field>::ZERO,
        C::test_context(),
        OsRng,
    );
    assert_eq!(
        response.unwrap_err(),
        ErrorCode::InvalidAmount,
        "Zero credit amount should be rejected"
    );
}

pub(crate) fn test_spend_zero_for_reanonymization<C: TestCiphersuite>() {
    let private_key = PrivateKey::<C>::random(OsRng);
    let preissuance = PreIssuance::<C>::random(OsRng);
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let request = preissuance.request(&params, OsRng);
    let initial_credits = C::scalar_from_u128(100);
    let response = private_key
        .issue::<128>(&params, &request, initial_credits, C::test_context(), OsRng)
        .unwrap();
    let token = preissuance
        .to_credit_token::<128>(&params, private_key.public(), &request, &response)
        .unwrap();

    // Spend zero to re-anonymize
    let (spend_proof, prerefund) = token
        .prove_spend::<128>(&params, <C::Scalar as Field>::ZERO, OsRng)
        .unwrap();
    assert_eq!(prerefund.m, initial_credits, "Balance should be unchanged");

    let refund = private_key
        .refund(
            &params,
            &spend_proof,
            <C::Scalar as Field>::ZERO,
            OsRng,
        )
        .unwrap();
    let new_token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();

    // New token has same balance but fresh nullifier
    assert_eq!(new_token.c, initial_credits);
    assert_ne!(
        new_token.k, token.k,
        "New token should have a different nullifier"
    );
}

pub(crate) fn test_exhaust_token_with_one_credit_spends<C: TestCiphersuite>() {
    let mut nullifier_db = NullifierDb::new();

    let private_key = PrivateKey::<C>::random(OsRng);
    let preissuance = PreIssuance::<C>::random(OsRng);
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let request = preissuance.request(&params, OsRng);
    let initial_credits = 10u128;
    let credit_amount = C::scalar_from_u128(initial_credits);

    let response = private_key
        .issue::<128>(&params, &request, credit_amount, C::test_context(), OsRng)
        .unwrap();
    let mut current_token = preissuance
        .to_credit_token::<128>(&params, private_key.public(), &request, &response)
        .unwrap();

    let spend_amount = C::scalar_from_u128(1);
    let mut remaining_credits = initial_credits;

    // Exhaust the token with 1-credit spends
    for i in 1..=initial_credits {
        assert_eq!(
            current_token.c,
            C::scalar_from_u128(remaining_credits),
            "Token should have {} credits before spend #{}",
            remaining_credits,
            i
        );

        let (spend_proof, prerefund) = current_token
            .prove_spend::<128>(&params, spend_amount, OsRng)
            .unwrap();
        remaining_credits -= 1;

        assert_eq!(
            prerefund.m,
            C::scalar_from_u128(remaining_credits),
            "Remaining balance should be {} after spend #{}",
            remaining_credits,
            i
        );

        let nullifier = spend_proof.nullifier();
        assert!(
            !nullifier_db.is_spent::<C>(&nullifier),
            "Nullifier already spent in iteration {}",
            i
        );
        nullifier_db.record_spent::<C>(&nullifier);

        let refund = private_key
            .refund(
                &params,
                &spend_proof,
                <C::Scalar as Field>::ZERO,
                OsRng,
            )
            .unwrap();
        current_token = prerefund
            .to_credit_token(&params, &spend_proof, &refund, private_key.public())
            .unwrap();
    }

    // Verify final token is empty
    assert_eq!(
        current_token.c,
        <C::Scalar as Field>::ZERO,
        "Final token should have zero balance"
    );

    // Try to spend from empty token
    let result = current_token.prove_spend::<128>(&params, spend_amount, OsRng);
    assert!(result.is_err(), "Spending from an empty token should fail");

    // But spending zero should work
    let zero_spend = <C::Scalar as Field>::ZERO;
    let (spend_proof, prerefund) = current_token
        .prove_spend::<128>(&params, zero_spend, OsRng)
        .unwrap();
    let refund = private_key
        .refund(
            &params,
            &spend_proof,
            <C::Scalar as Field>::ZERO,
            OsRng,
        )
        .unwrap();
    let new_token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();
    assert_eq!(
        new_token.c,
        <C::Scalar as Field>::ZERO,
        "New token should still have zero balance"
    );
}

pub(crate) fn test_binary_decomposition_max_value<C: TestCiphersuite>() {
    let max_value = C::scalar_from_u128(u128::MAX);
    let private_key = PrivateKey::<C>::random(OsRng);
    let preissuance = PreIssuance::<C>::random(OsRng);
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let request = preissuance.request(&params, OsRng);

    let response = private_key
        .issue::<128>(&params, &request, max_value, C::test_context(), OsRng)
        .unwrap();
    let token = preissuance
        .to_credit_token::<128>(&params, private_key.public(), &request, &response)
        .unwrap();

    assert_eq!(token.c, max_value, "Token should have the maximum value");

    // Spend a small amount
    let spend_amount = C::scalar_from_u128(1);
    let (spend_proof, prerefund) = token
        .prove_spend::<128>(&params, spend_amount, OsRng)
        .unwrap();

    let refund = private_key
        .refund(
            &params,
            &spend_proof,
            <C::Scalar as Field>::ZERO,
            OsRng,
        )
        .unwrap();
    let new_token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();

    let expected_remaining = max_value - spend_amount;
    assert_eq!(
        new_token.c, expected_remaining,
        "Remaining balance incorrect after spending from max value"
    );

    // Spend the entire remaining balance
    let (spend_proof2, prerefund2) = new_token
        .prove_spend::<128>(&params, expected_remaining, OsRng)
        .unwrap();

    let refund2 = private_key
        .refund(
            &params,
            &spend_proof2,
            <C::Scalar as Field>::ZERO,
            OsRng,
        )
        .unwrap();
    let final_token = prerefund2
        .to_credit_token(&params, &spend_proof2, &refund2, private_key.public())
        .unwrap();

    assert_eq!(
        final_token.c,
        <C::Scalar as Field>::ZERO,
        "Final token should have zero balance"
    );
}

pub(crate) fn test_transcript_with_empty_input<C: TestCiphersuite>() {
    let label = b"empty_test";
    let params = Params::<C>::random(OsRng);

    // Create a transcript with no elements
    let gamma = Transcript::<C>::with(&params.transcript_base, label, |_transcript| {
        // No elements added
    });

    assert_ne!(
        gamma,
        <C::Scalar as Field>::ZERO,
        "Challenge should not be zero"
    );
    assert_ne!(
        gamma,
        <C::Scalar as Field>::ONE,
        "Challenge should not be one"
    );

    // Create another transcript with the same empty input
    let gamma2 = Transcript::<C>::with(&params.transcript_base, label, |_transcript| {
        // No elements added
    });

    assert_eq!(
        gamma, gamma2,
        "Challenges with same empty input should match"
    );

    // Create a transcript with a different label
    let gamma3 =
        Transcript::<C>::with(&params.transcript_base, b"different_label", |_transcript| {
            // No elements added
        });

    assert_ne!(
        gamma, gamma3,
        "Challenges with different labels should not match"
    );
}

pub(crate) fn test_nullifier_collisions<C: TestCiphersuite>() {
    let mut nullifier_db = NullifierDb::new();

    let private_key = PrivateKey::<C>::random(OsRng);
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();

    let num_tokens = 30;

    for i in 0..num_tokens {
        let preissuance = PreIssuance::<C>::random(OsRng);
        let request = preissuance.request(&params, OsRng);
        let credit_amount = C::scalar_from_u128(100);

        let response = private_key
            .issue::<128>(&params, &request, credit_amount, C::test_context(), OsRng)
            .unwrap();
        let token = preissuance
            .to_credit_token::<128>(&params, private_key.public(), &request, &response)
            .unwrap();

        let (spend_proof, _) = token
            .prove_spend::<128>(&params, C::scalar_from_u128(1), OsRng)
            .unwrap();

        let nullifier = spend_proof.nullifier();
        let is_duplicate = nullifier_db.is_spent::<C>(&nullifier);

        assert!(!is_duplicate, "Detected nullifier collision at token {}", i);

        nullifier_db.record_spent::<C>(&nullifier);
    }

    assert_eq!(
        nullifier_db.used_nullifiers.len(),
        num_tokens,
        "Should have exactly {} unique nullifiers",
        num_tokens
    );
}

pub(crate) fn test_key_component_malleability<C: TestCiphersuite>() {
    let private_key = PrivateKey::<C>::random(OsRng);
    let preissuance = PreIssuance::<C>::random(OsRng);
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let request = preissuance.request(&params, OsRng);
    let credit_amount = C::scalar_from_u128(50);

    let response = private_key
        .issue::<128>(&params, &request, credit_amount, C::test_context(), OsRng)
        .unwrap();
    let token = preissuance
        .to_credit_token::<128>(&params, private_key.public(), &request, &response)
        .unwrap();

    let (spend_proof, prerefund) = token
        .prove_spend::<128>(&params, C::scalar_from_u128(10), OsRng)
        .unwrap();

    let refund = private_key
        .refund(
            &params,
            &spend_proof,
            <C::Scalar as Field>::ZERO,
            OsRng,
        )
        .unwrap();

    // 1. Tamper with the 'a' component
    let generator = C::generator_mul(&<C::Scalar as Field>::ONE);
    let tampered_refund1 = Refund {
        a: refund.a + generator,
        e: refund.e,
        gamma: refund.gamma,
        z: refund.z,
        t: refund.t,
    };
    let result1 = prerefund.to_credit_token(
        &params,
        &spend_proof,
        &tampered_refund1,
        private_key.public(),
    );
    assert!(
        result1.is_err(),
        "Tampered 'a' component should be rejected"
    );

    // 2. Tamper with the 'e' component
    let tampered_refund_e = Refund {
        a: refund.a,
        e: refund.e + <C::Scalar as Field>::ONE,
        gamma: refund.gamma,
        z: refund.z,
        t: refund.t,
    };
    let result_e = prerefund.to_credit_token(
        &params,
        &spend_proof,
        &tampered_refund_e,
        private_key.public(),
    );
    assert!(
        result_e.is_err(),
        "Tampered 'e' component should be rejected"
    );

    // 3. Tamper with the 'gamma' component
    let tampered_refund2 = Refund {
        a: refund.a,
        e: refund.e,
        gamma: refund.gamma + <C::Scalar as Field>::ONE,
        z: refund.z,
        t: refund.t,
    };
    let result2 = prerefund.to_credit_token(
        &params,
        &spend_proof,
        &tampered_refund2,
        private_key.public(),
    );
    assert!(
        result2.is_err(),
        "Tampered 'gamma' component should be rejected"
    );

    // 4. Tamper with the 'z' component
    let tampered_refund3 = Refund {
        a: refund.a,
        e: refund.e,
        gamma: refund.gamma,
        z: refund.z + <C::Scalar as Field>::ONE,
        t: refund.t,
    };
    let result3 = prerefund.to_credit_token(
        &params,
        &spend_proof,
        &tampered_refund3,
        private_key.public(),
    );
    assert!(
        result3.is_err(),
        "Tampered 'z' component should be rejected"
    );

    // 5. Tamper with the 't' component
    let tampered_refund4 = Refund {
        a: refund.a,
        e: refund.e,
        gamma: refund.gamma,
        z: refund.z,
        t: refund.t + <C::Scalar as Field>::ONE,
    };
    let result4 = prerefund.to_credit_token(
        &params,
        &spend_proof,
        &tampered_refund4,
        private_key.public(),
    );
    assert!(
        result4.is_err(),
        "Tampered 't' component should be rejected"
    );

    // The original refund should still be valid
    let result5 = prerefund.to_credit_token(&params, &spend_proof, &refund, private_key.public());
    assert!(result5.is_ok(), "Original refund should be valid");
}

pub(crate) fn test_full_cycle_small_l<C: TestCiphersuite>() {
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let private_key = PrivateKey::<C>::random(OsRng);

    macro_rules! test_with_l {
        ($l:expr, $amount:expr, $spend:expr) => {{
            let preissuance = PreIssuance::<C>::random(OsRng);
            let request = preissuance.request(&params, OsRng);
            let credit_amount = C::scalar_from_u128($amount);
            let spend_amount = C::scalar_from_u128($spend);

            let response = private_key
                .issue::<$l>(&params, &request, credit_amount, C::test_context(), OsRng)
                .unwrap();
            let token = preissuance
                .to_credit_token::<$l>(&params, private_key.public(), &request, &response)
                .unwrap();

            let (spend_proof, prerefund) =
                token.prove_spend::<$l>(&params, spend_amount, OsRng).unwrap();

            assert_eq!(prerefund.m, C::scalar_from_u128($amount - $spend));

            let refund = private_key
                .refund(
                    &params,
                    &spend_proof,
                    <C::Scalar as Field>::ZERO,
                    OsRng,
                )
                .unwrap();
            let new_token = prerefund
                .to_credit_token(&params, &spend_proof, &refund, private_key.public())
                .unwrap();

            assert_eq!(new_token.c, C::scalar_from_u128($amount - $spend));
        }};
    }

    test_with_l!(1, 1u128, 1u128);
    test_with_l!(2, 3u128, 1u128);
    test_with_l!(4, 10u128, 5u128);
    test_with_l!(8, 100u128, 50u128);
    test_with_l!(16, 1000u128, 500u128);
    test_with_l!(32, 50000u128, 25000u128);
    test_with_l!(64, 1000000u128, 999999u128);
    test_with_l!(128, 1000000u128, 999999u128);
}

pub(crate) fn test_issue_rejects_out_of_range_for_small_l<C: TestCiphersuite>() {
    const TINY_L: usize = 8;

    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let private_key = PrivateKey::<C>::random(OsRng);
    let preissuance = PreIssuance::<C>::random(OsRng);
    let issuance_request = preissuance.request(&params, OsRng);

    // 255 should succeed
    let result = private_key.issue::<TINY_L>(
        &params,
        &issuance_request,
        C::scalar_from_u128(255),
        C::test_context(),
        OsRng,
    );
    assert!(result.is_ok(), "255 should be valid for L=8");

    // 256 should fail
    let result = private_key.issue::<TINY_L>(
        &params,
        &issuance_request,
        C::scalar_from_u128(256),
        C::test_context(),
        OsRng,
    );
    assert_eq!(
        result.unwrap_err(),
        ErrorCode::InvalidAmount,
        "256 should be rejected for L=8"
    );
}

pub(crate) fn test_credit_to_scalar_small_l<C: TestCiphersuite>() {
    // With L=8, amounts >= 256 should be rejected
    assert!(credit_to_scalar::<C, 8>(0).is_ok());
    assert!(credit_to_scalar::<C, 8>(255).is_ok());
    assert!(credit_to_scalar::<C, 8>(256).is_err());
    assert!(credit_to_scalar::<C, 8>(1000).is_err());

    // With L=128, all u128 values should be valid
    assert!(credit_to_scalar::<C, 128>(0).is_ok());
    assert!(credit_to_scalar::<C, 128>(u128::MAX).is_ok());
}

pub(crate) fn test_multiple_l_values<C: TestCiphersuite>() {
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let private_key = PrivateKey::<C>::random(OsRng);

    macro_rules! test_full_cycle_with_l {
        ($l:expr, $amount:expr, $spend:expr) => {{
            let preissuance = PreIssuance::<C>::random(OsRng);
            let request = preissuance.request(&params, OsRng);
            let credit_amount = C::scalar_from_u128($amount as u128);
            let spend_amount = C::scalar_from_u128($spend as u128);

            let response = private_key
                .issue::<$l>(&params, &request, credit_amount, C::test_context(), OsRng)
                .unwrap();
            let token = preissuance
                .to_credit_token::<$l>(&params, private_key.public(), &request, &response)
                .unwrap();

            let (spend_proof, prerefund) =
                token.prove_spend::<$l>(&params, spend_amount, OsRng).unwrap();
            let refund = private_key
                .refund(
                    &params,
                    &spend_proof,
                    <C::Scalar as Field>::ZERO,
                    OsRng,
                )
                .unwrap();
            let new_token = prerefund
                .to_credit_token(&params, &spend_proof, &refund, private_key.public())
                .unwrap();
            assert_eq!(
                new_token.c,
                C::scalar_from_u128(($amount - $spend) as u128)
            );
        }};
    }

    test_full_cycle_with_l!(8, 100, 30);
    test_full_cycle_with_l!(16, 1000, 500);
    test_full_cycle_with_l!(32, 50000, 25000);
    test_full_cycle_with_l!(64, 1000000, 999999);
    test_full_cycle_with_l!(128, 1000000, 999999);
}

pub(crate) fn test_partial_return_basic<C: TestCiphersuite>() {
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let private_key = PrivateKey::<C>::random(OsRng);

    // Issue 100 credits, spend 30 with t=10 -> 80
    let token = issue_token::<C>(&params, &private_key, 100);
    let new_token = spend_with_return::<C>(&params, &private_key, &token, 30, 10);
    assert_eq!(new_token.c, C::scalar_from_u128(80));

    // Spend 20 from the 80-credit token with t=0 -> 60
    let final_token = spend_with_return::<C>(&params, &private_key, &new_token, 20, 0);
    assert_eq!(final_token.c, C::scalar_from_u128(60));
}

pub(crate) fn test_partial_return_full_return<C: TestCiphersuite>() {
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let private_key = PrivateKey::<C>::random(OsRng);

    // Issue 100, spend 50 with t=50 (return everything) -> 100
    let token = issue_token::<C>(&params, &private_key, 100);
    let new_token = spend_with_return::<C>(&params, &private_key, &token, 50, 50);
    assert_eq!(new_token.c, C::scalar_from_u128(100));
}

pub(crate) fn test_partial_return_zero<C: TestCiphersuite>() {
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let private_key = PrivateKey::<C>::random(OsRng);

    // Issue 100, spend 30 with t=0 -> 70
    let token = issue_token::<C>(&params, &private_key, 100);
    let new_token = spend_with_return::<C>(&params, &private_key, &token, 30, 0);
    assert_eq!(new_token.c, C::scalar_from_u128(70));
}

pub(crate) fn test_partial_return_one_credit<C: TestCiphersuite>() {
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let private_key = PrivateKey::<C>::random(OsRng);

    // Issue 100, spend 30 with t=1 -> 71
    let token = issue_token::<C>(&params, &private_key, 100);
    let new_token = spend_with_return::<C>(&params, &private_key, &token, 30, 1);
    assert_eq!(new_token.c, C::scalar_from_u128(71));
}

pub(crate) fn test_partial_return_t_equals_s<C: TestCiphersuite>() {
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let private_key = PrivateKey::<C>::random(OsRng);

    for s in [1u128, 5, 10, 25, 50, 99, 100] {
        let token = issue_token::<C>(&params, &private_key, 100);
        let new_token = spend_with_return::<C>(&params, &private_key, &token, s, s);
        assert_eq!(
            new_token.c,
            C::scalar_from_u128(100),
            "Token should still have 100 credits when t=s={}",
            s
        );
    }
}

pub(crate) fn test_prove_spend_rejects_overspend<C: TestCiphersuite>() {
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let private_key = PrivateKey::<C>::random(OsRng);

    let token = issue_token::<C>(&params, &private_key, 100);

    // s > c should fail
    let result = token.prove_spend::<128>(&params, C::scalar_from_u128(101), OsRng);
    assert_eq!(result.unwrap_err(), ErrorCode::InvalidAmount);

    // s == c should succeed
    let result = token.prove_spend::<128>(&params, C::scalar_from_u128(100), OsRng);
    assert!(result.is_ok());
}

pub(crate) fn test_prove_spend_rejects_s_exceeding_l_bits<C: TestCiphersuite>() {
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let private_key = PrivateKey::<C>::random(OsRng);

    // Use L=8: issue 100, try spending 256 (>= 2^8)
    let preissuance = PreIssuance::<C>::random(OsRng);
    let request = preissuance.request(&params, OsRng);
    let response = private_key
        .issue::<8>(
            &params,
            &request,
            C::scalar_from_u128(100),
            C::test_context(),
            OsRng,
        )
        .unwrap();
    let token = preissuance
        .to_credit_token::<8>(&params, private_key.public(), &request, &response)
        .unwrap();

    let result = token.prove_spend::<8>(&params, C::scalar_from_u128(256), OsRng);
    assert_eq!(result.unwrap_err(), ErrorCode::InvalidAmount);
}

pub(crate) fn test_partial_return_t_exceeds_s_rejected<C: TestCiphersuite>() {
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let private_key = PrivateKey::<C>::random(OsRng);

    let token = issue_token::<C>(&params, &private_key, 100);
    let (spend_proof, _) = token
        .prove_spend::<128>(&params, C::scalar_from_u128(30), OsRng)
        .unwrap();
    let result = private_key.refund(&params, &spend_proof, C::scalar_from_u128(31), OsRng);
    assert_eq!(result.unwrap_err(), ErrorCode::InvalidAmount);
}

pub(crate) fn test_partial_return_t_exceeds_l_bits_rejected<C: TestCiphersuite>() {
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let private_key = PrivateKey::<C>::random(OsRng);

    // Use L=8: issue 100, spend 30, try t=256 (>= 2^8)
    let preissuance = PreIssuance::<C>::random(OsRng);
    let request = preissuance.request(&params, OsRng);
    let response = private_key
        .issue::<8>(
            &params,
            &request,
            C::scalar_from_u128(100),
            C::test_context(),
            OsRng,
        )
        .unwrap();
    let token = preissuance
        .to_credit_token::<8>(&params, private_key.public(), &request, &response)
        .unwrap();

    let (spend_proof, _) = token
        .prove_spend::<8>(&params, C::scalar_from_u128(30), OsRng)
        .unwrap();
    let result = private_key.refund::<8>(&params, &spend_proof, C::scalar_from_u128(256), OsRng);
    assert_eq!(result.unwrap_err(), ErrorCode::InvalidAmount);
}

pub(crate) fn test_partial_return_sequential_chain<C: TestCiphersuite>() {
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let private_key = PrivateKey::<C>::random(OsRng);

    // start=100, spend 20 return 5 (=85), spend 30 return 10 (=65),
    // spend 15 return 15 (=65), spend 40 return 0 (=25), spend 25 return 0 (=0)
    let token = issue_token::<C>(&params, &private_key, 100);

    let token = spend_with_return::<C>(&params, &private_key, &token, 20, 5);
    assert_eq!(token.c, C::scalar_from_u128(85));

    let token = spend_with_return::<C>(&params, &private_key, &token, 30, 10);
    assert_eq!(token.c, C::scalar_from_u128(65));

    let token = spend_with_return::<C>(&params, &private_key, &token, 15, 15);
    assert_eq!(token.c, C::scalar_from_u128(65));

    let token = spend_with_return::<C>(&params, &private_key, &token, 40, 0);
    assert_eq!(token.c, C::scalar_from_u128(25));

    let token = spend_with_return::<C>(&params, &private_key, &token, 25, 0);
    assert_eq!(token.c, <C::Scalar as Field>::ZERO);
}

pub(crate) fn test_partial_return_preauth_pattern<C: TestCiphersuite>() {
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let private_key = PrivateKey::<C>::random(OsRng);

    // Issue 1000 credits
    let token = issue_token::<C>(&params, &private_key, 1000);

    // Hold 200 (spend 200), actually consume 150 (return 50) -> 850
    let token = spend_with_return::<C>(&params, &private_key, &token, 200, 50);
    assert_eq!(token.c, C::scalar_from_u128(850));

    // Hold 300, consume 300 (return 0) -> 550
    let token = spend_with_return::<C>(&params, &private_key, &token, 300, 0);
    assert_eq!(token.c, C::scalar_from_u128(550));
}

pub(crate) fn test_partial_return_then_reanonymize<C: TestCiphersuite>() {
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let private_key = PrivateKey::<C>::random(OsRng);

    // Issue 100, spend 30 with t=10 -> 80
    let token = issue_token::<C>(&params, &private_key, 100);
    let token = spend_with_return::<C>(&params, &private_key, &token, 30, 10);
    assert_eq!(token.c, C::scalar_from_u128(80));

    let old_nullifier = token.nullifier();

    // Re-anonymize: spend 0 with t=0 -> still 80 with fresh nullifier
    let token = spend_with_return::<C>(&params, &private_key, &token, 0, 0);
    assert_eq!(token.c, C::scalar_from_u128(80));
    assert_ne!(token.nullifier(), old_nullifier);
}

pub(crate) fn test_partial_return_spend_full_remaining<C: TestCiphersuite>() {
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let private_key = PrivateKey::<C>::random(OsRng);

    // Issue 100, spend 30 with t=10 -> 80
    let token = issue_token::<C>(&params, &private_key, 100);
    let token = spend_with_return::<C>(&params, &private_key, &token, 30, 10);
    assert_eq!(token.c, C::scalar_from_u128(80));

    // Spend all 80 with t=0 -> 0
    let token = spend_with_return::<C>(&params, &private_key, &token, 80, 0);
    assert_eq!(token.c, <C::Scalar as Field>::ZERO);
}

pub(crate) fn test_partial_return_nullifier_still_tracked<C: TestCiphersuite>() {
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let private_key = PrivateKey::<C>::random(OsRng);
    let mut nullifier_db = NullifierDb::new();

    let token = issue_token::<C>(&params, &private_key, 100);
    let (spend_proof, prerefund) = token
        .prove_spend::<128>(&params, C::scalar_from_u128(30), OsRng)
        .unwrap();

    // Record nullifier
    let nullifier = spend_proof.nullifier();
    assert!(!nullifier_db.is_spent::<C>(&nullifier));
    nullifier_db.record_spent::<C>(&nullifier);

    // Issue refund with partial return
    let refund = private_key
        .refund(&params, &spend_proof, C::scalar_from_u128(10), OsRng)
        .unwrap();
    let new_token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();
    assert_eq!(new_token.c, C::scalar_from_u128(80));

    // The original nullifier is still the one tracked
    assert!(nullifier_db.is_spent::<C>(&nullifier));
    // New token has a different nullifier
    assert!(!nullifier_db.is_spent::<C>(&new_token.nullifier()));
}

pub(crate) fn test_partial_return_different_t_values_different_tokens<C: TestCiphersuite>() {
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let private_key = PrivateKey::<C>::random(OsRng);

    let token = issue_token::<C>(&params, &private_key, 100);
    let (spend_proof, prerefund) = token
        .prove_spend::<128>(&params, C::scalar_from_u128(30), OsRng)
        .unwrap();

    // Process two refunds with different t values from same spend proof
    let refund1 = private_key
        .refund(&params, &spend_proof, C::scalar_from_u128(5), OsRng)
        .unwrap();
    let token1 = prerefund
        .to_credit_token(&params, &spend_proof, &refund1, private_key.public())
        .unwrap();

    let refund2 = private_key
        .refund(&params, &spend_proof, C::scalar_from_u128(10), OsRng)
        .unwrap();
    let token2 = prerefund
        .to_credit_token(&params, &spend_proof, &refund2, private_key.public())
        .unwrap();

    assert_eq!(token1.c, C::scalar_from_u128(75));
    assert_eq!(token2.c, C::scalar_from_u128(80));
}

pub(crate) fn test_partial_return_max_credits_l8<C: TestCiphersuite>() {
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let private_key = PrivateKey::<C>::random(OsRng);

    // Use L=8, issue 255 (max for L=8), spend 255, return 255 -> 255
    let preissuance = PreIssuance::<C>::random(OsRng);
    let request = preissuance.request(&params, OsRng);
    let response = private_key
        .issue::<8>(
            &params,
            &request,
            C::scalar_from_u128(255),
            C::test_context(),
            OsRng,
        )
        .unwrap();
    let token = preissuance
        .to_credit_token::<8>(&params, private_key.public(), &request, &response)
        .unwrap();

    let (spend_proof, prerefund) = token
        .prove_spend::<8>(&params, C::scalar_from_u128(255), OsRng)
        .unwrap();
    let refund = private_key
        .refund::<8>(&params, &spend_proof, C::scalar_from_u128(255), OsRng)
        .unwrap();
    let new_token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();
    assert_eq!(new_token.c, C::scalar_from_u128(255));
}

pub(crate) fn test_partial_return_with_nonzero_ctx<C: TestCiphersuite>() {
    let params = Params::<C>::new("test-org", "test-service", "test-env", "2024-01-01").unwrap();
    let private_key = PrivateKey::<C>::random(OsRng);

    // Issue with nonzero ctx
    let preissuance = PreIssuance::<C>::random(OsRng);
    let request = preissuance.request(&params, OsRng);
    let ctx = C::test_context(); // nonzero
    let response = private_key
        .issue::<128>(&params, &request, C::scalar_from_u128(100), ctx, OsRng)
        .unwrap();
    let token = preissuance
        .to_credit_token::<128>(&params, private_key.public(), &request, &response)
        .unwrap();

    // Spend 30 with t=10 -> 80
    let (spend_proof, prerefund) = token
        .prove_spend::<128>(&params, C::scalar_from_u128(30), OsRng)
        .unwrap();
    assert_eq!(spend_proof.context(), ctx);

    let refund = private_key
        .refund(&params, &spend_proof, C::scalar_from_u128(10), OsRng)
        .unwrap();
    let new_token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();
    assert_eq!(new_token.c, C::scalar_from_u128(80));

    // ctx is preserved: spend from new token and check
    let (spend_proof2, _) = new_token
        .prove_spend::<128>(&params, C::scalar_from_u128(10), OsRng)
        .unwrap();
    assert_eq!(spend_proof2.context(), ctx);
}

// ── instantiate_tests macro ────────────────────────────────────────────

/// Generates `#[test]` items that call every generic test function for a
/// concrete ciphersuite type `$C`.
#[macro_export]
macro_rules! instantiate_tests {
    ($C:ty) => {
        #[test]
        fn issuance() {
            $crate::tests_common::test_issuance::<$C>();
        }
        #[test]
        fn full_cycle() {
            $crate::tests_common::test_full_cycle::<$C>();
        }
        #[test]
        fn double_spend_prevention() {
            $crate::tests_common::test_double_spend_prevention::<$C>();
        }
        #[test]
        fn spend_exact_balance() {
            $crate::tests_common::test_spend_exact_balance::<$C>();
        }
        #[test]
        fn sequential_spends() {
            $crate::tests_common::test_sequential_spends::<$C>();
        }
        #[test]
        fn attempt_overspend() {
            $crate::tests_common::test_attempt_overspend::<$C>();
        }
        #[test]
        fn zero_spend_scenario() {
            $crate::tests_common::test_zero_spend_scenario::<$C>();
        }
        #[test]
        fn multiple_tokens_with_same_issuer() {
            $crate::tests_common::test_multiple_tokens_with_same_issuer::<$C>();
        }
        #[test]
        fn bits_of_() {
            $crate::tests_common::test_bits_of::<$C>();
        }
        #[test]
        fn invalid_issuance_request() {
            $crate::tests_common::test_invalid_issuance_request::<$C>();
        }
        #[test]
        fn invalid_proof_verification() {
            $crate::tests_common::test_invalid_proof_verification::<$C>();
        }
        #[test]
        fn large_amount_issuance() {
            $crate::tests_common::test_large_amount_issuance::<$C>();
        }
        #[test]
        fn invalid_token_verification() {
            $crate::tests_common::test_invalid_token_verification::<$C>();
        }
        #[test]
        fn transcript_add_elements_test() {
            $crate::tests_common::test_transcript_add_elements::<$C>();
        }
        #[test]
        fn tampered_refund_verification() {
            $crate::tests_common::test_tampered_refund_verification::<$C>();
        }
        #[test]
        fn zero_e_signature_attack() {
            $crate::tests_common::test_zero_e_signature_attack::<$C>();
        }
        #[test]
        fn spend_with_identity_a_prime() {
            $crate::tests_common::test_spend_with_identity_a_prime::<$C>();
        }
        #[test]
        fn issuance_rejects_zero_credits() {
            $crate::tests_common::test_issuance_rejects_zero_credits::<$C>();
        }
        #[test]
        fn spend_zero_for_reanonymization() {
            $crate::tests_common::test_spend_zero_for_reanonymization::<$C>();
        }
        #[test]
        fn exhaust_token_with_one_credit_spends() {
            $crate::tests_common::test_exhaust_token_with_one_credit_spends::<$C>();
        }
        #[test]
        fn test_binary_decomposition_max_value() {
            $crate::tests_common::test_binary_decomposition_max_value::<$C>();
        }
        #[test]
        fn test_transcript_with_empty_input() {
            $crate::tests_common::test_transcript_with_empty_input::<$C>();
        }
        #[test]
        fn test_nullifier_collisions() {
            $crate::tests_common::test_nullifier_collisions::<$C>();
        }
        #[test]
        fn test_key_component_malleability() {
            $crate::tests_common::test_key_component_malleability::<$C>();
        }
        #[test]
        fn full_cycle_small_l() {
            $crate::tests_common::test_full_cycle_small_l::<$C>();
        }
        #[test]
        fn issue_rejects_out_of_range_for_small_l() {
            $crate::tests_common::test_issue_rejects_out_of_range_for_small_l::<$C>();
        }
        #[test]
        fn credit_to_scalar_small_l() {
            $crate::tests_common::test_credit_to_scalar_small_l::<$C>();
        }
        #[test]
        fn multiple_l_values() {
            $crate::tests_common::test_multiple_l_values::<$C>();
        }
        #[test]
        fn partial_return_basic() {
            $crate::tests_common::test_partial_return_basic::<$C>();
        }
        #[test]
        fn partial_return_full_return() {
            $crate::tests_common::test_partial_return_full_return::<$C>();
        }
        #[test]
        fn partial_return_zero() {
            $crate::tests_common::test_partial_return_zero::<$C>();
        }
        #[test]
        fn partial_return_one_credit() {
            $crate::tests_common::test_partial_return_one_credit::<$C>();
        }
        #[test]
        fn partial_return_t_equals_s() {
            $crate::tests_common::test_partial_return_t_equals_s::<$C>();
        }
        #[test]
        fn prove_spend_rejects_overspend() {
            $crate::tests_common::test_prove_spend_rejects_overspend::<$C>();
        }
        #[test]
        fn prove_spend_rejects_s_exceeding_l_bits() {
            $crate::tests_common::test_prove_spend_rejects_s_exceeding_l_bits::<$C>();
        }
        #[test]
        fn partial_return_t_exceeds_s_rejected() {
            $crate::tests_common::test_partial_return_t_exceeds_s_rejected::<$C>();
        }
        #[test]
        fn partial_return_t_exceeds_l_bits_rejected() {
            $crate::tests_common::test_partial_return_t_exceeds_l_bits_rejected::<$C>();
        }
        #[test]
        fn partial_return_sequential_chain() {
            $crate::tests_common::test_partial_return_sequential_chain::<$C>();
        }
        #[test]
        fn partial_return_preauth_pattern() {
            $crate::tests_common::test_partial_return_preauth_pattern::<$C>();
        }
        #[test]
        fn partial_return_then_reanonymize() {
            $crate::tests_common::test_partial_return_then_reanonymize::<$C>();
        }
        #[test]
        fn partial_return_spend_full_remaining() {
            $crate::tests_common::test_partial_return_spend_full_remaining::<$C>();
        }
        #[test]
        fn partial_return_nullifier_still_tracked() {
            $crate::tests_common::test_partial_return_nullifier_still_tracked::<$C>();
        }
        #[test]
        fn partial_return_different_t_values_different_tokens() {
            $crate::tests_common::test_partial_return_different_t_values_different_tokens::<$C>();
        }
        #[test]
        fn partial_return_max_credits_l8() {
            $crate::tests_common::test_partial_return_max_credits_l8::<$C>();
        }
        #[test]
        fn partial_return_with_nonzero_ctx() {
            $crate::tests_common::test_partial_return_with_nonzero_ctx::<$C>();
        }
    };
}
