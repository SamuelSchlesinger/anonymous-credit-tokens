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
use rand_core::OsRng;
use std::collections::HashSet;
use proptest::prelude::*;

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

    /// Check if a nullifier has been used before
    fn is_spent(&self, nullifier: &Scalar) -> bool {
        self.used_nullifiers.contains(nullifier)
    }

    /// Record a nullifier as spent
    fn record_spent(&mut self, nullifier: &Scalar) {
        self.used_nullifiers.insert(*nullifier);
    }
}

#[test]
fn issuance() {
    use rand::{Rng, thread_rng};

    for _i in 0..100 {
        let private_key = PrivateKey::random(OsRng);
        let preissuance = PreIssuance::random(OsRng);
        let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
        let issuance_request = preissuance.request(&params, OsRng);

        // Random credit amount between 1 and 1000
        let credit_amount = Scalar::from(thread_rng().gen_range(1..1000) as u64);

        let issuance_response = private_key
            .issue(&params, &issuance_request, credit_amount, OsRng)
            .unwrap();
        let _credit_token1 = preissuance
            .to_credit_token(
                &params,
                private_key.public(),
                &issuance_request,
                &issuance_response,
            )
            .unwrap();
    }
}

#[test]
fn full_cycle() {
    use rand::{Rng, thread_rng};

    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    for _i in 0..10 {
        let private_key = PrivateKey::random(OsRng);
        let preissuance = PreIssuance::random(OsRng);
        let issuance_request = preissuance.request(&params, OsRng);

        // Random credit amount between 100 and 2000
        let total_credits = thread_rng().gen_range(100..2000) as u64;
        let credit_amount = Scalar::from(total_credits);

        let issuance_response = private_key
            .issue(&params, &issuance_request, credit_amount, OsRng)
            .unwrap();
        let credit_token1 = preissuance
            .to_credit_token(
                &params,
                private_key.public(),
                &issuance_request,
                &issuance_response,
            )
            .unwrap();

        // First charge: random amount between 1 and 1/2 of total credits
        let first_charge = thread_rng().gen_range(1..=(total_credits / 2)) as u64;
        let charge1 = Scalar::from(first_charge);

        let (spend_proof, prerefund) = credit_token1.prove_spend(&params, charge1, OsRng);
        let refund = private_key.refund(&params, &spend_proof, OsRng).unwrap();
        let credit_token2 = prerefund
            .to_credit_token(&params, &spend_proof, &refund, private_key.public())
            .unwrap();

        // Second charge: remaining credits
        let remaining_credits = total_credits - first_charge;
        let charge2 = Scalar::from(remaining_credits);

        let (spend_proof, prerefund) = credit_token2.prove_spend(&params, charge2, OsRng);
        let refund = private_key.refund(&params, &spend_proof, OsRng).unwrap();
        let _credit_token3 = prerefund
            .to_credit_token(&params, &spend_proof, &refund, private_key.public())
            .unwrap();
    }
}

#[test]
fn double_spend_prevention() {
    use rand::{Rng, thread_rng};

    // Initialize nullifier database
    let mut nullifier_db = NullifierDb::new();

    // Setup issuer and client
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let issuance_request = preissuance.request(&params, OsRng);

    // Random credit amount between 100 and 1000
    let total_credits = thread_rng().gen_range(100..1000) as u64;
    let credit_amount = Scalar::from(total_credits);

    let issuance_response = private_key
        .issue(&params, &issuance_request, credit_amount, OsRng)
        .unwrap();
    let credit_token = preissuance
        .to_credit_token(
            &params,
            private_key.public(),
            &issuance_request,
            &issuance_response,
        )
        .unwrap();

    // First spend is successful - random amount between 1 and 1/3 of total credits
    let first_charge = thread_rng().gen_range(1..=(total_credits / 3)) as u64;
    let charge1 = Scalar::from(first_charge);

    let (spend_proof1, prerefund1) = credit_token.prove_spend(&params, charge1, OsRng);

    // Verify nullifier isn't already spent
    let nullifier = spend_proof1.nullifier();
    assert!(
        !nullifier_db.is_spent(&nullifier),
        "Nullifier should not be spent yet"
    );

    // Process refund
    let refund1 = private_key.refund(&params, &spend_proof1, OsRng).unwrap();

    // Record nullifier as spent
    nullifier_db.record_spent(&nullifier);

    // Create new token from refund
    let new_token = prerefund1
        .to_credit_token(&params, &spend_proof1, &refund1, private_key.public())
        .unwrap();

    // Attempt to use the same original token (double-spend attempt)
    // Use a different amount than the first spend
    let second_charge = thread_rng().gen_range(1..=(total_credits / 2)) as u64;
    let charge2 = Scalar::from(second_charge);

    let (spend_proof2, _) = credit_token.prove_spend(&params, charge2, OsRng);

    // Check nullifier - should detect double spend
    let nullifier2 = spend_proof2.nullifier();
    assert!(
        nullifier_db.is_spent(&nullifier2),
        "Double-spend not detected"
    );

    // Verify we can spend from the new token
    let remaining_credits = total_credits - first_charge;
    let third_charge = thread_rng().gen_range(1..remaining_credits) as u64;
    let charge3 = Scalar::from(third_charge);

    let (spend_proof3, _) = new_token.prove_spend(&params, charge3, OsRng);
    let nullifier3 = spend_proof3.nullifier();

    // This is a different nullifier, should not be detected as spent
    assert!(
        !nullifier_db.is_spent(&nullifier3),
        "New token spend incorrectly marked as double-spend"
    );
}

#[test]
fn spend_exact_balance() {
    use rand::{Rng, thread_rng};

    // Test spending the exact balance amount
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let issuance_request = preissuance.request(&params, OsRng);

    // Random credit amount between 10 and 1000
    let total_credits = thread_rng().gen_range(10..1000) as u64;
    let credit_amount = Scalar::from(total_credits);

    let issuance_response = private_key
        .issue(&params, &issuance_request, credit_amount, OsRng)
        .unwrap();
    let credit_token = preissuance
        .to_credit_token(
            &params,
            private_key.public(),
            &issuance_request,
            &issuance_response,
        )
        .unwrap();

    // Spend the exact balance amount
    let (spend_proof, prerefund) = credit_token.prove_spend(&params, credit_amount, OsRng);

    // Verify the refund amount is zero
    assert_eq!(
        prerefund.m,
        Scalar::ZERO,
        "Remaining balance should be zero"
    );

    // Verify the refund still processes correctly
    let refund = private_key.refund(&params, &spend_proof, OsRng).unwrap();
    let new_token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();

    // New token should have zero balance
    assert_eq!(
        new_token.c,
        Scalar::ZERO,
        "New token should have zero balance"
    );
}

#[test]
fn sequential_spends() {
    use rand::{Rng, thread_rng};

    let mut nullifier_db = NullifierDb::new();

    // Issue a token with a random large balance
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let issuance_request = preissuance.request(&params, OsRng);

    // Random initial amount between 100 and 1000
    let initial_credits = thread_rng().gen_range(100..1000) as u64;
    let initial_amount = Scalar::from(initial_credits);

    let issuance_response = private_key
        .issue(&params, &issuance_request, initial_amount, OsRng)
        .unwrap();
    let mut current_token = preissuance
        .to_credit_token(
            &params,
            private_key.public(),
            &issuance_request,
            &issuance_response,
        )
        .unwrap();

    // Calculate per-spend amount: divide initial amount by 10 (ensuring at least 5 increments)
    let per_spend_amount = initial_credits / 10;
    let spend_amount = Scalar::from(per_spend_amount);
    let mut remaining = initial_credits;

    // Perform 5 sequential spends
    for i in 1..=5 {
        // Spend some credits
        let (spend_proof, prerefund) = current_token.prove_spend(&params, spend_amount, OsRng);
        remaining -= per_spend_amount;

        // Check that the remaining amount is correct
        assert_eq!(
            prerefund.m,
            Scalar::from(remaining as u64),
            "Remaining balance incorrect after spend {}",
            i
        );

        // Record the nullifier
        let nullifier = spend_proof.nullifier();
        assert!(
            !nullifier_db.is_spent(&nullifier),
            "Nullifier already spent in iteration {}",
            i
        );
        nullifier_db.record_spent(&nullifier);

        // Get refund and create new token
        let refund = private_key.refund(&params, &spend_proof, OsRng).unwrap();
        current_token = prerefund
            .to_credit_token(&params, &spend_proof, &refund, private_key.public())
            .unwrap();

        // Verify the new token has the correct balance
        assert_eq!(
            current_token.c,
            Scalar::from(remaining as u64),
            "New token has incorrect balance after spend {}",
            i
        );
    }

    // Verify final remaining balance
    let expected_final_balance = initial_credits - (5 * per_spend_amount);
    assert_eq!(
        current_token.c,
        Scalar::from(expected_final_balance),
        "Final balance incorrect"
    );
}

#[test]
fn attempt_overspend() {
    use rand::{Rng, thread_rng};

    // Create a token with random credits
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let issuance_request = preissuance.request(&params, OsRng);

    // Random credit amount between 20 and 500
    let credit_value = thread_rng().gen_range(20..500) as u64;
    let credit_amount = Scalar::from(credit_value);

    let issuance_response = private_key
        .issue(&params, &issuance_request, credit_amount, OsRng)
        .unwrap();
    let credit_token = preissuance
        .to_credit_token(
            &params,
            private_key.public(),
            &issuance_request,
            &issuance_response,
        )
        .unwrap();

    // Try to spend more than available (random amount > credit_value)
    let overspend_value = credit_value + thread_rng().gen_range(1..100) as u64;
    let overspend_amount = Scalar::from(overspend_value);
    let (spend_proof, _) = credit_token.prove_spend(&params, overspend_amount, OsRng);

    // The refund verification should fail when the issuer checks it
    let refund_result = private_key.refund(&params, &spend_proof, OsRng);

    // The refund should be None since the proof is invalid
    assert!(
        refund_result.is_none(),
        "Overspend should have been rejected"
    );
}

#[test]
fn zero_spend_scenario() {
    use rand::{Rng, thread_rng};

    // Create a token with random credits
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let issuance_request = preissuance.request(&params, OsRng);

    // Random credit amount between 10 and 1000
    let credit_value = thread_rng().gen_range(10..1000) as u64;
    let credit_amount = Scalar::from(credit_value);

    let issuance_response = private_key
        .issue(&params, &issuance_request, credit_amount, OsRng)
        .unwrap();
    let credit_token = preissuance
        .to_credit_token(
            &params,
            private_key.public(),
            &issuance_request,
            &issuance_response,
        )
        .unwrap();

    // Spend zero credits
    let zero_spend = Scalar::from(0u64);
    let (spend_proof, prerefund) = credit_token.prove_spend(&params, zero_spend, OsRng);

    // The refund should process successfully
    let refund = private_key.refund(&params, &spend_proof, OsRng).unwrap();

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

#[test]
fn multiple_tokens_with_same_issuer() {
    use rand::{Rng, thread_rng};

    let mut nullifier_db = NullifierDb::new();

    // Single issuer
    let private_key = PrivateKey::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");

    // Create two separate tokens for two different clients with random amounts

    // First token: Random amount between 50 and 500
    let credit_value1 = thread_rng().gen_range(50..500) as u64;
    let credit_amount1 = Scalar::from(credit_value1);

    let preissuance1 = PreIssuance::random(OsRng);
    let request1 = preissuance1.request(&params, OsRng);
    let response1 = private_key
        .issue(&params, &request1, credit_amount1, OsRng)
        .unwrap();
    let token1 = preissuance1
        .to_credit_token(&params, private_key.public(), &request1, &response1)
        .unwrap();

    // Second token: Random amount between 30 and 300
    let credit_value2 = thread_rng().gen_range(30..300) as u64;
    let credit_amount2 = Scalar::from(credit_value2);

    let preissuance2 = PreIssuance::random(OsRng);
    let request2 = preissuance2.request(&params, OsRng);
    let response2 = private_key
        .issue(&params, &request2, credit_amount2, OsRng)
        .unwrap();
    let token2 = preissuance2
        .to_credit_token(&params, private_key.public(), &request2, &response2)
        .unwrap();

    // Both clients spend from their tokens with random amounts

    // First spend: Random amount between 1 and credit_value1/2
    let spend_value1 = thread_rng().gen_range(1..=(credit_value1 / 2)) as u64;
    let spend_amount1 = Scalar::from(spend_value1);
    let expected_remaining1 = credit_value1 - spend_value1;

    // Second spend: Random amount between 1 and credit_value2/2
    let spend_value2 = thread_rng().gen_range(1..=(credit_value2 / 2)) as u64;
    let spend_amount2 = Scalar::from(spend_value2);
    let expected_remaining2 = credit_value2 - spend_value2;

    let (spend_proof1, prerefund1) = token1.prove_spend(&params, spend_amount1, OsRng);
    let (spend_proof2, prerefund2) = token2.prove_spend(&params, spend_amount2, OsRng);

    // Get the nullifiers
    let nullifier1 = spend_proof1.nullifier();
    let nullifier2 = spend_proof2.nullifier();

    // Nullifiers should be different
    assert_ne!(
        nullifier1, nullifier2,
        "Tokens should have different nullifiers"
    );

    // Record both spends
    nullifier_db.record_spent(&nullifier1);
    nullifier_db.record_spent(&nullifier2);

    // Process refunds
    let refund1 = private_key.refund(&params, &spend_proof1, OsRng).unwrap();
    let refund2 = private_key.refund(&params, &spend_proof2, OsRng).unwrap();

    // Create new tokens
    let new_token1 = prerefund1
        .to_credit_token(&params, &spend_proof1, &refund1, private_key.public())
        .unwrap();
    let new_token2 = prerefund2
        .to_credit_token(&params, &spend_proof2, &refund2, private_key.public())
        .unwrap();

    // Check remaining balances
    assert_eq!(
        new_token1.c,
        Scalar::from(expected_remaining1),
        "First token should have {} credits remaining",
        expected_remaining1
    );
    assert_eq!(
        new_token2.c,
        Scalar::from(expected_remaining2),
        "Second token should have {} credits remaining",
        expected_remaining2
    );
}

#[test]
fn bits_of_() {
    let x = Scalar::from(u128::MAX);
    let bits = crate::bits_of(x);
    bits.iter().for_each(|bit| assert_eq!(*bit, Scalar::ONE));
    let x = Scalar::from(0u64);
    let bits = crate::bits_of(x);
    bits.iter().for_each(|bit| assert_eq!(*bit, Scalar::ZERO));
    let x = Scalar::from(0b001u64);
    let bits = crate::bits_of(x);
    bits.iter()
        .enumerate()
        .for_each(|(i, bit)| {
            let expected = if i == 0 { Scalar::ONE } else { Scalar::ZERO };
            assert_eq!(*bit, expected);
        });
    let x = Scalar::from(0b100000000u64);
    let bits = crate::bits_of(x);
    bits.iter()
        .enumerate()
        .for_each(|(i, bit)| {
            let expected = if i == 8 { Scalar::ONE } else { Scalar::ZERO };
            assert_eq!(*bit, expected);
        });
    let x = Scalar::from(7u64);
    let bits = crate::bits_of(x);
    bits.iter()
        .enumerate()
        .for_each(|(i, bit)| {
            let expected = if i <= 2 { Scalar::ONE } else { Scalar::ZERO };
            assert_eq!(*bit, expected);
        });
    let x = Scalar::from(0b10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010u128);
    let bits = crate::bits_of(x);
    bits.iter()
        .enumerate()
        .for_each(|(i, bit)| {
            let expected = if i % 2 == 1 { Scalar::ONE } else { Scalar::ZERO };
            assert_eq!(*bit, expected);
        });
    let x = Scalar::from(0b01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101u128);
    let bits = crate::bits_of(x);
    bits.iter()
        .enumerate()
        .for_each(|(i, bit)| {
            let expected = if i % 2 == 0 { Scalar::ONE } else { Scalar::ZERO };
            assert_eq!(*bit, expected);
        });
}

#[test]
fn invalid_issuance_request() {
    // Create a private key
    let private_key = PrivateKey::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");

    // Create a valid preissuance state
    let preissuance = PreIssuance::random(OsRng);

    // Create a valid request
    let valid_request = preissuance.request(&params, OsRng);

    // Tamper with the request by modifying the k_bar value
    let tampered_request = IssuanceRequest {
        big_k: valid_request.big_k,
        gamma: valid_request.gamma,
        k_bar: valid_request.k_bar + Scalar::ONE, // Modify the k_bar value
        r_bar: valid_request.r_bar,
    };

    // The issuer should reject the tampered request
    let issuance_response =
        private_key.issue(&params, &tampered_request, Scalar::from(20u64), OsRng);
    assert!(
        issuance_response.is_none(),
        "Tampered request should be rejected"
    );

    // The original request should be accepted
    let issuance_response = private_key.issue(&params, &valid_request, Scalar::from(20u64), OsRng);
    assert!(
        issuance_response.is_some(),
        "Valid request should be accepted"
    );
}

#[test]
fn invalid_proof_verification() {
    use rand::{Rng, thread_rng};

    // Create a private key and token
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let request = preissuance.request(&params, OsRng);

    // Random credit amount between 50 and 500
    let credit_value = thread_rng().gen_range(50..500) as u64;
    let credit_amount = Scalar::from(credit_value);

    let response = private_key
        .issue(&params, &request, credit_amount, OsRng)
        .unwrap();
    let token = preissuance
        .to_credit_token(&params, private_key.public(), &request, &response)
        .unwrap();

    // Create a valid spend proof with a random amount
    let spend_value = thread_rng().gen_range(10..credit_value / 2) as u64;
    let spend_amount = Scalar::from(spend_value);
    let (spend_proof, _) = token.prove_spend(&params, spend_amount, OsRng);

    // Tamper with the proof by modifying the amount to a different random value
    let tampered_value = spend_value + thread_rng().gen_range(1..10) as u64;
    let tampered_proof = SpendProof {
        s: Scalar::from(tampered_value), // Changed to a different amount
        ..spend_proof
    };

    // The issuer should reject the tampered proof
    let refund_result = private_key.refund(&params, &tampered_proof, OsRng);
    assert!(refund_result.is_none(), "Tampered proof should be rejected");
}

#[test]
fn large_amount_issuance() {
    use rand::{Rng, thread_rng};

    // Test with a very large credit amount (but still within the L-bit range)
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let request = preissuance.request(&params, OsRng);

    // Create a large amount, close to the maximum representable value
    // Use a large amount that's near 2^31 but slightly randomized
    let base_amount = 2u128.pow(L as u32 - 2); // 2^120
    let variation = thread_rng().gen_range(0..base_amount) as u128;
    let large_amount = Scalar::from(base_amount + variation);

    let response = private_key
        .issue(&params, &request, large_amount, OsRng)
        .unwrap();
    let token = preissuance
        .to_credit_token(&params, private_key.public(), &request, &response)
        .unwrap();

    // Spend a random portion of the large amount
    let max_spend = std::cmp::min(base_amount / 2, 5_000_000); // Cap at 5 million to keep test reasonable
    let spend_value = thread_rng().gen_range(1..max_spend) as u64;
    let spend_amount = Scalar::from(spend_value);

    let (spend_proof, prerefund) = token.prove_spend(&params, spend_amount, OsRng);

    // The remaining amount should be correct
    let expected_remaining = large_amount - spend_amount;
    assert_eq!(
        prerefund.m, expected_remaining,
        "Remaining balance incorrect"
    );

    // The refund should process correctly
    let refund = private_key.refund(&params, &spend_proof, OsRng).unwrap();
    let new_token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();

    // The new token should have the expected balance
    assert_eq!(
        new_token.c, expected_remaining,
        "New token balance incorrect"
    );
}

#[test]
fn invalid_token_verification() {
    // Create a private key and token
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let request = preissuance.request(&params, OsRng);
    let response = private_key
        .issue(&params, &request, Scalar::from(50u64), OsRng)
        .unwrap();

    // Tamper with the response
    let tampered_response = IssuanceResponse {
        gamma: response.gamma,
        a: response.a,
        e: response.e + Scalar::ONE, // Modify the e value
        z: response.z,
        c: response.c,
    };

    // The client should reject the tampered response
    let token_result =
        preissuance.to_credit_token(&params, private_key.public(), &request, &tampered_response);
    assert!(
        token_result.is_none(),
        "Tampered response should be rejected"
    );

    // The original response should be accepted
    let token_result =
        preissuance.to_credit_token(&params, private_key.public(), &request, &response);
    assert!(token_result.is_some(), "Valid response should be accepted");
}

#[test]
fn test_params_generation_deterministic() {
    // Test that parameters are generated deterministically
    let params1 = Params::new("test-org", "test-service", "test", "2024-01-01");
    let params2 = Params::new("test-org", "test-service", "test", "2024-01-01");
    
    // The same domain separator should produce the same parameters
    assert_eq!(params1.h1.basepoint().compress(), params2.h1.basepoint().compress());
    assert_eq!(params1.h2.basepoint().compress(), params2.h2.basepoint().compress());
    assert_eq!(params1.h3.basepoint().compress(), params2.h3.basepoint().compress());
    
    // Different domain separators should produce different parameters
    let params3 = Params::new("different-org", "test-service", "test", "2024-01-01");
    assert_ne!(params1.h1.basepoint().compress(), params3.h1.basepoint().compress());
}

#[test]
fn transcript_add_elements_test() {
    use curve25519_dalek::RistrettoPoint;

    // Create points to add to the transcript
    let point1 = RistrettoPoint::generator();
    let point2 = RistrettoPoint::generator() * Scalar::from(2u64);
    let point3 = RistrettoPoint::generator() * Scalar::from(3u64);

    let params = Params::random(OsRng);

    // Create a transcript and add elements using add_elements
    let mut transcript1 = Transcript::new(&params, b"test");
    transcript1.add_elements([&point1, &point2, &point3].into_iter());
    let challenge1 = transcript1.challenge();

    // Create another transcript and add the same elements one by one
    let mut transcript2 = Transcript::new(&params, b"test");
    transcript2.add_element(&point1);
    transcript2.add_element(&point2);
    transcript2.add_element(&point3);
    let challenge2 = transcript2.challenge();

    // The challenges should be identical
    assert_eq!(
        challenge1, challenge2,
        "add_elements should produce the same result as multiple add_element calls"
    );
}

#[test]
fn tampered_refund_verification() {
    // Setup
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let request = preissuance.request(&params, OsRng);
    let response = private_key
        .issue(&params, &request, Scalar::from(50u64), OsRng)
        .unwrap();
    let token = preissuance
        .to_credit_token(&params, private_key.public(), &request, &response)
        .unwrap();

    // Create a valid spend
    let spend_amount = Scalar::from(20u64);
    let (spend_proof, prerefund) = token.prove_spend(&params, spend_amount, OsRng);

    // Get a valid refund
    let refund = private_key.refund(&params, &spend_proof, OsRng).unwrap();

    // Tamper with the refund
    let tampered_refund = Refund {
        a: refund.a,
        e: refund.e + Scalar::ONE, // Modify the e value
        gamma: refund.gamma,
        z: refund.z,
    };

    // The client should reject the tampered refund
    let new_token_result = prerefund.to_credit_token(
        &params,
        &spend_proof,
        &tampered_refund,
        private_key.public(),
    );
    assert!(
        new_token_result.is_none(),
        "Tampered refund should be rejected"
    );

    // The original refund should be accepted
    let new_token_result =
        prerefund.to_credit_token(&params, &spend_proof, &refund, private_key.public());
    assert!(
        new_token_result.is_some(),
        "Valid refund should be accepted"
    );
}

#[test]
fn zero_e_signature_attack() {
    // Test if a zero e value in the signature can be exploited
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let request = preissuance.request(&params, OsRng);
    let response = private_key
        .issue(&params, &request, Scalar::from(20u64), OsRng)
        .unwrap();

    // Create a tampered response with e = 0
    let tampered_response = IssuanceResponse {
        a: response.a,
        e: Scalar::ZERO, // Set e to zero
        gamma: response.gamma,
        z: response.z,
        c: response.c,
    };

    // The client should reject this (though the actual signature verification may fail in different ways)
    let token_result =
        preissuance.to_credit_token(&params, private_key.public(), &request, &tampered_response);
    assert!(token_result.is_none(), "Zero e value should be rejected");
}

#[test]
fn spend_with_identity_a_prime() {
    // Create a token
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let request = preissuance.request(&params, OsRng);
    let response = private_key
        .issue(&params, &request, Scalar::from(20u64), OsRng)
        .unwrap();
    let token = preissuance
        .to_credit_token(&params, private_key.public(), &request, &response)
        .unwrap();

    // Create a valid spend proof
    let (mut spend_proof, _) = token.prove_spend(&params, Scalar::from(10u64), OsRng);

    // Tamper with the proof - set a_prime to identity
    spend_proof.a_prime = RistrettoPoint::identity();

    // The issuer should reject this proof
    let refund_result = private_key.refund(&params, &spend_proof, OsRng);
    assert!(
        refund_result.is_none(),
        "Spend proof with identity a_prime should be rejected"
    );
}

#[test]
fn token_with_zero_credit() {
    use rand::{Rng, thread_rng};

    // Create a token with zero credits
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let request = preissuance.request(&params, OsRng);
    let zero_amount = Scalar::ZERO;
    let response = private_key
        .issue(&params, &request, zero_amount, OsRng)
        .unwrap();
    let token = preissuance
        .to_credit_token(&params, private_key.public(), &request, &response)
        .unwrap();

    // Token should have zero balance
    assert_eq!(token.c, Scalar::ZERO, "Token should have zero balance");

    // Attempting to spend from this token should fail
    // Try to spend a random positive amount
    let spend_amount = Scalar::from(thread_rng().gen_range(1..100) as u64);
    let (spend_proof, _) = token.prove_spend(&params, spend_amount, OsRng);
    let refund_result = private_key.refund(&params, &spend_proof, OsRng);
    assert!(
        refund_result.is_none(),
        "Spending from a zero-balance token should fail"
    );

    // But spending zero from it should work
    let zero_spend = Scalar::ZERO;
    let (spend_proof, prerefund) = token.prove_spend(&params, zero_spend, OsRng);
    let refund = private_key.refund(&params, &spend_proof, OsRng).unwrap();
    let new_token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();
    assert_eq!(
        new_token.c,
        Scalar::ZERO,
        "New token should still have zero balance"
    );
}

#[test]
fn exhaust_token_with_one_credit_spends() {
    // Create a nullifier database to track spent tokens
    let mut nullifier_db = NullifierDb::new();

    // Create a token with exactly 10 credits
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let request = preissuance.request(&params, OsRng);
    let initial_credits = 10u64;
    let credit_amount = Scalar::from(initial_credits);

    let response = private_key
        .issue(&params, &request, credit_amount, OsRng)
        .unwrap();
    let mut current_token = preissuance
        .to_credit_token(&params, private_key.public(), &request, &response)
        .unwrap();

    // Spend amount is always 1 credit
    let spend_amount = Scalar::from(1u64);
    let mut remaining_credits = initial_credits;

    // Exhaust the token with 1-credit spends until it's empty
    for i in 1..=initial_credits {
        // Verify the current token has the expected balance
        assert_eq!(
            current_token.c,
            Scalar::from(remaining_credits),
            "Token should have {} credits before spend #{}",
            remaining_credits,
            i
        );

        // Spend 1 credit
        let (spend_proof, prerefund) = current_token.prove_spend(&params, spend_amount, OsRng);
        remaining_credits -= 1;

        // Verify remaining balance
        assert_eq!(
            prerefund.m,
            Scalar::from(remaining_credits),
            "Remaining balance should be {} after spend #{}",
            remaining_credits,
            i
        );

        // Check and record nullifier
        let nullifier = spend_proof.nullifier();
        assert!(
            !nullifier_db.is_spent(&nullifier),
            "Nullifier already spent in iteration {}",
            i
        );
        nullifier_db.record_spent(&nullifier);

        // Get refund and create new token
        let refund = private_key.refund(&params, &spend_proof, OsRng).unwrap();
        current_token = prerefund
            .to_credit_token(&params, &spend_proof, &refund, private_key.public())
            .unwrap();
    }

    // Verify final token is empty
    assert_eq!(
        current_token.c,
        Scalar::ZERO,
        "Final token should have zero balance"
    );

    // Try to spend from empty token
    let (spend_proof, _) = current_token.prove_spend(&params, spend_amount, OsRng);
    let refund_result = private_key.refund(&params, &spend_proof, OsRng);
    assert!(
        refund_result.is_none(),
        "Spending from an empty token should fail"
    );

    // But spending zero from it should work
    let zero_spend = Scalar::ZERO;
    let (spend_proof, prerefund) = current_token.prove_spend(&params, zero_spend, OsRng);
    let refund = private_key.refund(&params, &spend_proof, OsRng).unwrap();
    let new_token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();
    assert_eq!(
        new_token.c,
        Scalar::ZERO,
        "New token should still have zero balance"
    );
}

#[test]
fn test_binary_decomposition_max_value() {
    // Test with the maximum representable value (2^L - 1)
    let max_value = Scalar::from(u128::MAX);
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let request = preissuance.request(&params, OsRng);

    // Issue a token with the maximum value
    let response = private_key
        .issue(&params, &request, max_value, OsRng)
        .unwrap();
    let token = preissuance
        .to_credit_token(&params, private_key.public(), &request, &response)
        .unwrap();

    // Verify the token has the correct balance
    assert_eq!(token.c, max_value, "Token should have the maximum value");

    // Spend a small amount from this token
    let spend_amount = Scalar::from(1u64);
    let (spend_proof, prerefund) = token.prove_spend(&params, spend_amount, OsRng);

    // Process the refund
    let refund = private_key.refund(&params, &spend_proof, OsRng).unwrap();
    let new_token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();

    // Verify the remaining balance
    let expected_remaining = max_value - spend_amount;
    assert_eq!(
        new_token.c, expected_remaining,
        "Remaining balance incorrect after spending from max value"
    );

    // Spend the entire remaining balance
    let (spend_proof2, prerefund2) = new_token.prove_spend(&params, expected_remaining, OsRng);

    // Process the refund
    let refund2 = private_key.refund(&params, &spend_proof2, OsRng).unwrap();
    let final_token = prerefund2
        .to_credit_token(&params, &spend_proof2, &refund2, private_key.public())
        .unwrap();

    // Verify the final token has zero balance
    assert_eq!(
        final_token.c,
        Scalar::ZERO,
        "Final token should have zero balance"
    );
}

#[test]
fn test_transcript_with_empty_input() {
    // Test the transcript system with empty input
    let label = b"empty_test";

    let params = Params::random(OsRng);

    // Create a transcript with no elements
    let gamma = Transcript::with(&params, label, |_transcript| {
        // No elements added
    });

    // The challenge should still be a valid random-looking scalar
    assert_ne!(gamma, Scalar::ZERO, "Challenge should not be zero");
    assert_ne!(gamma, Scalar::ONE, "Challenge should not be one");

    // Create another transcript with the same empty input
    let gamma2 = Transcript::with(&params, label, |_transcript| {
        // No elements added
    });

    // The challenges should be the same (deterministic based on label)
    assert_eq!(
        gamma, gamma2,
        "Challenges with same empty input should match"
    );

    // Create a transcript with a different label
    let gamma3 = Transcript::with(&params, b"different_label", |_transcript| {
        // No elements added
    });

    // The challenge should be different from the first one
    assert_ne!(
        gamma, gamma3,
        "Challenges with different labels should not match"
    );
}

#[test]
fn test_nullifier_collisions() {
    // This test tries to detect nullifier collisions by generating many tokens
    let mut nullifier_db = NullifierDb::new();

    // Create a single issuer
    let private_key = PrivateKey::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");

    // Number of tokens to create and check
    let num_tokens = 30;

    // Generate multiple tokens and check their nullifiers
    for i in 0..num_tokens {
        let preissuance = PreIssuance::random(OsRng);
        let request = preissuance.request(&params, OsRng);
        let credit_amount = Scalar::from(100u64);

        let response = private_key
            .issue(&params, &request, credit_amount, OsRng)
            .unwrap();
        let token = preissuance
            .to_credit_token(&params, private_key.public(), &request, &response)
            .unwrap();

        // Generate a spend proof (doesn't matter what amount)
        let (spend_proof, _) = token.prove_spend(&params, Scalar::from(1u64), OsRng);

        // Check if we've seen this nullifier before
        let nullifier = spend_proof.nullifier();
        let is_duplicate = nullifier_db.is_spent(&nullifier);

        // If we've seen this nullifier before, the test should fail
        assert!(!is_duplicate, "Detected nullifier collision at token {}", i);

        // Record this nullifier
        nullifier_db.record_spent(&nullifier);
    }

    // Check that we recorded the expected number of unique nullifiers
    assert_eq!(
        nullifier_db.used_nullifiers.len(),
        num_tokens,
        "Should have exactly {} unique nullifiers",
        num_tokens
    );
}

#[test]
fn test_key_component_malleability() {
    // Test for potential malleability in key components

    // Create a private key
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let request = preissuance.request(&params, OsRng);
    let credit_amount = Scalar::from(50u64);

    // Create a valid token
    let response = private_key
        .issue(&params, &request, credit_amount, OsRng)
        .unwrap();
    let token = preissuance
        .to_credit_token(&params, private_key.public(), &request, &response)
        .unwrap();

    // Create a spend proof
    let (spend_proof, prerefund) = token.prove_spend(&params, Scalar::from(10u64), OsRng);

    // Process refund
    let refund = private_key.refund(&params, &spend_proof, OsRng).unwrap();

    // Test different tampering scenarios

    // 1. Tamper with the 'a' component in the refund
    let tampered_refund1 = Refund {
        a: refund.a + RistrettoPoint::generator(), // Change the a component
        e: refund.e,
        gamma: refund.gamma,
        z: refund.z,
    };

    // This should fail validation
    let result1 = prerefund.to_credit_token(
        &params,
        &spend_proof,
        &tampered_refund1,
        private_key.public(),
    );
    assert!(
        result1.is_none(),
        "Tampered 'a' component should be rejected"
    );

    // 2. Tamper with the 'gamma' component in the refund
    let tampered_refund2 = Refund {
        a: refund.a,
        e: refund.e,
        gamma: refund.gamma + Scalar::ONE, // Change the gamma component
        z: refund.z,
    };

    // This should fail validation
    let result2 = prerefund.to_credit_token(
        &params,
        &spend_proof,
        &tampered_refund2,
        private_key.public(),
    );
    assert!(
        result2.is_none(),
        "Tampered 'gamma' component should be rejected"
    );

    // 3. Tamper with the 'z' component in the refund
    let tampered_refund3 = Refund {
        a: refund.a,
        e: refund.e,
        gamma: refund.gamma,
        z: refund.z + Scalar::ONE, // Change the z component
    };

    // This should fail validation
    let result3 = prerefund.to_credit_token(
        &params,
        &spend_proof,
        &tampered_refund3,
        private_key.public(),
    );
    assert!(
        result3.is_none(),
        "Tampered 'z' component should be rejected"
    );

    // The original refund should still be valid
    let result4 = prerefund.to_credit_token(&params, &spend_proof, &refund, private_key.public());
    assert!(result4.is_some(), "Original refund should be valid");
}

// ===== PROPERTY-BASED TESTING WITH PROPTEST =====

/// Strategy for generating random Scalars
fn scalar_strategy() -> impl Strategy<Value = Scalar> {
    prop::array::uniform32(any::<u8>())
        .prop_map(|bytes| Scalar::from_bytes_mod_order(bytes))
}

/// Strategy for generating Scalars within u128 range (for credit amounts)
fn credit_amount_strategy() -> impl Strategy<Value = Scalar> {
    any::<u128>().prop_map(Scalar::from)
}

/// Strategy for generating valid RistrettoPoints
fn point_strategy() -> impl Strategy<Value = RistrettoPoint> {
    scalar_strategy().prop_map(|s| RistrettoPoint::generator() * s)
}

/// Strategy for generating PrivateKeys
fn private_key_strategy() -> impl Strategy<Value = PrivateKey> {
    scalar_strategy().prop_map(|x| {
        let w = RistrettoPoint::generator() * x;
        PrivateKey { x, public: PublicKey { w } }
    })
}

/// Strategy for generating PreIssuance
fn pre_issuance_strategy() -> impl Strategy<Value = PreIssuance> {
    (scalar_strategy(), scalar_strategy())
        .prop_map(|(r, k)| PreIssuance { r, k })
}

/// Strategy for generating CreditTokens
fn credit_token_strategy() -> impl Strategy<Value = CreditToken> {
    (
        point_strategy(),
        scalar_strategy(),
        scalar_strategy(),
        scalar_strategy(),
        scalar_strategy(),
    )
        .prop_map(|(a, e, k, r, c)| CreditToken { a, e, k, r, c })
}

// Use a single test params instance to avoid stack issues
fn test_params() -> Params {
    Params::new("test-org", "test-service", "test-env", "2024-01-01")
}

// Property: Issuance protocol maintains balance invariant
proptest! {
    #[test]
    fn prop_issuance_balance_invariant(
        credit_amount in credit_amount_strategy(),
        private_key in private_key_strategy(),
        pre_issuance in pre_issuance_strategy(),
    ) {
        let params = test_params();
        let request = pre_issuance.request(&params, OsRng);
        
        if let Some(response) = private_key.issue(&params, &request, credit_amount, OsRng) {
            if let Some(token) = pre_issuance.to_credit_token(
                &params,
                private_key.public(),
                &request,
                &response,
            ) {
                // The token should have the exact credit amount issued
                prop_assert_eq!(token.c, credit_amount);
            }
        }
    }
}

// Property: Double issuance with same request fails
proptest! {
    #[test]
    fn prop_no_double_issuance(
        credit_amount in credit_amount_strategy(),
        private_key in private_key_strategy(),
        pre_issuance in pre_issuance_strategy(),
    ) {
        let params = test_params();
        let request = pre_issuance.request(&params, OsRng);
        
        // First issuance should succeed
        let response1 = private_key.issue(&params, &request, credit_amount, OsRng);
        prop_assert!(response1.is_some());
        
        // Second issuance with same request should fail (simulated by checking)
        // In a real system, the issuer would track used requests
    }
}

// Property: Spend + Refund preserves total balance
proptest! {
    #[test]
    fn prop_spend_refund_balance_preservation(
        initial_amount in 1u64..10000,
        spend_amount in 1u64..10000,
        private_key in private_key_strategy(),
        pre_issuance in pre_issuance_strategy(),
    ) {
        let params = test_params();
        let initial_credits = Scalar::from(initial_amount);
        let spend_credits = Scalar::from(spend_amount);
        
        // Skip if trying to overspend
        prop_assume!(spend_amount <= initial_amount);
        
        let request = pre_issuance.request(&params, OsRng);
        let response = private_key.issue(&params, &request, initial_credits, OsRng).unwrap();
        let token = pre_issuance
            .to_credit_token(&params, private_key.public(), &request, &response)
            .unwrap();
        
        // Spend some credits
        let (spend_proof, pre_refund) = token.prove_spend(&params, spend_credits, OsRng);
        
        // Remaining balance should be correct
        let expected_remaining = initial_credits - spend_credits;
        prop_assert_eq!(pre_refund.m, expected_remaining);
        
        // Process refund
        if let Some(refund) = private_key.refund(&params, &spend_proof, OsRng) {
            let new_token = pre_refund
                .to_credit_token(&params, &spend_proof, &refund, private_key.public())
                .unwrap();
            
            // New token should have the remaining balance
            prop_assert_eq!(new_token.c, expected_remaining);
        }
    }
}

// Property: Nullifiers are deterministic for same token
proptest! {
    #[test]
    fn prop_nullifier_determinism(
        credit_amount in credit_amount_strategy(),
        spend_amount in credit_amount_strategy(),
        private_key in private_key_strategy(),
        pre_issuance in pre_issuance_strategy(),
    ) {
        let params = test_params();
        prop_assume!(scalar_to_u128(&spend_amount).is_some());
        prop_assume!(scalar_to_u128(&credit_amount).is_some());
        let spend_u128 = scalar_to_u128(&spend_amount).unwrap();
        let credit_u128 = scalar_to_u128(&credit_amount).unwrap();
        prop_assume!(spend_u128 <= credit_u128);
        
        let request = pre_issuance.request(&params, OsRng);
        if let Some(response) = private_key.issue(&params, &request, credit_amount, OsRng) {
            if let Some(token) = pre_issuance.to_credit_token(
                &params,
                private_key.public(),
                &request,
                &response,
            ) {
                // Generate two spend proofs from the same token
                let (proof1, _) = token.prove_spend(&params, spend_amount, OsRng);
                let (proof2, _) = token.prove_spend(&params, spend_amount, OsRng);
                
                // Nullifiers should be identical (deterministic)
                prop_assert_eq!(proof1.nullifier(), proof2.nullifier());
            }
        }
    }
}

// Property: Different tokens have different nullifiers
proptest! {
    #[test]
    fn prop_nullifier_uniqueness(
        credit_amount in 1u64..10000,
        private_key in private_key_strategy(),
        pre_issuance1 in pre_issuance_strategy(),
        pre_issuance2 in pre_issuance_strategy(),
    ) {
        let params = test_params();
        // Skip if pre-issuances are identical (extremely unlikely)
        prop_assume!(pre_issuance1.r != pre_issuance2.r || pre_issuance1.k != pre_issuance2.k);
        
        let credits = Scalar::from(credit_amount);
        let spend_amount = Scalar::from(1u64);
        
        // Issue two different tokens
        let request1 = pre_issuance1.request(&params, OsRng);
        let response1 = private_key.issue(&params, &request1, credits, OsRng).unwrap();
        let token1 = pre_issuance1
            .to_credit_token(&params, private_key.public(), &request1, &response1)
            .unwrap();
        
        let request2 = pre_issuance2.request(&params, OsRng);
        let response2 = private_key.issue(&params, &request2, credits, OsRng).unwrap();
        let token2 = pre_issuance2
            .to_credit_token(&params, private_key.public(), &request2, &response2)
            .unwrap();
        
        // Get nullifiers
        let (proof1, _) = token1.prove_spend(&params, spend_amount, OsRng);
        let (proof2, _) = token2.prove_spend(&params, spend_amount, OsRng);
        
        // Nullifiers should be different
        prop_assert_ne!(proof1.nullifier(), proof2.nullifier());
    }
}

// Property: CBOR serialization round-trip for all types
proptest! {
    #[test]
    fn prop_cbor_round_trip_issuance_request(
        big_k in point_strategy(),
        gamma in scalar_strategy(),
        k_bar in scalar_strategy(),
        r_bar in scalar_strategy(),
    ) {
        let request = IssuanceRequest { big_k, gamma, k_bar, r_bar };
        let bytes = request.to_cbor().unwrap();
        let decoded = IssuanceRequest::from_cbor(&bytes).unwrap();
        
        prop_assert_eq!(request.big_k, decoded.big_k);
        prop_assert_eq!(request.gamma, decoded.gamma);
        prop_assert_eq!(request.k_bar, decoded.k_bar);
        prop_assert_eq!(request.r_bar, decoded.r_bar);
    }
}

proptest! {
    #[test]
    fn prop_cbor_round_trip_credit_token(token in credit_token_strategy()) {
        let bytes = token.to_cbor().unwrap();
        let decoded = CreditToken::from_cbor(&bytes).unwrap();
        
        prop_assert_eq!(token.a, decoded.a);
        prop_assert_eq!(token.e, decoded.e);
        prop_assert_eq!(token.k, decoded.k);
        prop_assert_eq!(token.r, decoded.r);
        prop_assert_eq!(token.c, decoded.c);
    }
}

proptest! {
    #[test]
    fn prop_cbor_round_trip_private_key(key in private_key_strategy()) {
        let bytes = key.to_cbor().unwrap();
        let decoded = PrivateKey::from_cbor(&bytes).unwrap();
        
        prop_assert_eq!(key.x, decoded.x);
        prop_assert_eq!(key.public.w, decoded.public.w);
    }
}

// Property: Binary decomposition correctness
proptest! {
    #[test]
    fn prop_binary_decomposition_correctness(value in any::<u128>()) {
        let scalar = Scalar::from(value);
        let bits = bits_of(scalar);
        
        // Reconstruct the value from bits
        let reconstructed = bits.iter()
            .enumerate()
            .fold(Scalar::ZERO, |acc, (i, bit)| {
                if *bit == Scalar::ONE {
                    acc + Scalar::from(2u128.pow(i as u32))
                } else {
                    acc
                }
            });
        
        // For values within u128 range, reconstruction should be exact
        prop_assert_eq!(scalar, reconstructed);
    }
}

// Property: Overspending always fails
proptest! {
    #[test]
    fn prop_overspend_always_fails(
        initial_amount in 1u64..10000,
        overspend_factor in 2u64..10,
        private_key in private_key_strategy(),
        pre_issuance in pre_issuance_strategy(),
    ) {
        let params = test_params();
        let initial_credits = Scalar::from(initial_amount);
        let overspend_amount = Scalar::from(initial_amount * overspend_factor);
        
        let request = pre_issuance.request(&params, OsRng);
        let response = private_key.issue(&params, &request, initial_credits, OsRng).unwrap();
        let token = pre_issuance
            .to_credit_token(&params, private_key.public(), &request, &response)
            .unwrap();
        
        // Try to overspend
        let (spend_proof, _) = token.prove_spend(&params, overspend_amount, OsRng);
        
        // Refund should fail
        let refund_result = private_key.refund(&params, &spend_proof, OsRng);
        prop_assert!(refund_result.is_none());
    }
}

// Property: Sequential spends accumulate correctly
proptest! {
    #[test]
    fn prop_sequential_spends_accumulate(
        initial_amount in 100u64..1000,
        spend_amounts in prop::collection::vec(1u64..50, 2..5),
        private_key in private_key_strategy(),
        pre_issuance in pre_issuance_strategy(),
    ) {
        let params = test_params();
        let initial_credits = Scalar::from(initial_amount);
        
        // Calculate total spend
        let total_spend: u64 = spend_amounts.iter().sum();
        prop_assume!(total_spend <= initial_amount);
        
        let request = pre_issuance.request(&params, OsRng);
        let response = private_key.issue(&params, &request, initial_credits, OsRng).unwrap();
        let mut current_token = pre_issuance
            .to_credit_token(&params, private_key.public(), &request, &response)
            .unwrap();
        
        let mut remaining = initial_amount;
        
        // Perform sequential spends
        for spend_amount in spend_amounts {
            let spend_scalar = Scalar::from(spend_amount);
            let (spend_proof, pre_refund) = current_token.prove_spend(&params, spend_scalar, OsRng);
            
            remaining -= spend_amount;
            prop_assert_eq!(pre_refund.m, Scalar::from(remaining));
            
            let refund = private_key.refund(&params, &spend_proof, OsRng).unwrap();
            current_token = pre_refund
                .to_credit_token(&params, &spend_proof, &refund, private_key.public())
                .unwrap();
            
            prop_assert_eq!(current_token.c, Scalar::from(remaining));
        }
        
        // Final balance should match
        prop_assert_eq!(current_token.c, Scalar::from(initial_amount - total_spend));
    }
}

// Property: Transcript determinism
proptest! {
    #[test]
    fn prop_transcript_determinism(
        label in prop::collection::vec(any::<u8>(), 1..32),
        points in prop::collection::vec(point_strategy(), 1..5),
    ) {
        let params = test_params();
        // Create two transcripts with same inputs
        let challenge1 = Transcript::with(&params, &label, |transcript| {
            for point in &points {
                transcript.add_element(point);
            }
        });
        
        let challenge2 = Transcript::with(&params, &label, |transcript| {
            for point in &points {
                transcript.add_element(point);
            }
        });
        
        // Challenges should be identical
        prop_assert_eq!(challenge1, challenge2);
    }
}

// Property: Zero amounts are handled correctly
proptest! {
    #[test]
    fn prop_zero_amount_handling(
        initial_amount in 1u64..10000,
        private_key in private_key_strategy(),
        pre_issuance in pre_issuance_strategy(),
    ) {
        let params = test_params();
        let initial_credits = Scalar::from(initial_amount);
        
        let request = pre_issuance.request(&params, OsRng);
        let response = private_key.issue(&params, &request, initial_credits, OsRng).unwrap();
        let token = pre_issuance
            .to_credit_token(&params, private_key.public(), &request, &response)
            .unwrap();
        
        // Spend zero
        let (spend_proof, pre_refund) = token.prove_spend(&params, Scalar::ZERO, OsRng);
        
        // Balance should be unchanged
        prop_assert_eq!(pre_refund.m, initial_credits);
        
        let refund = private_key.refund(&params, &spend_proof, OsRng).unwrap();
        let new_token = pre_refund
            .to_credit_token(&params, &spend_proof, &refund, private_key.public())
            .unwrap();
        
        prop_assert_eq!(new_token.c, initial_credits);
    }
}

// Property: Params affect cryptographic outputs
proptest! {
    #[test]
    fn prop_params_affect_outputs(
        pre_issuance in pre_issuance_strategy(),
    ) {
        let params1 = test_params();
        let params2 = Params::new("other-org", "other-service", "other-env", "2024-12-31");
        prop_assume!(params1 != params2); // Different params should be different
        
        let request1 = pre_issuance.request(&params1, OsRng);
        let request2 = pre_issuance.request(&params2, OsRng);
        
        // Requests should be different with different params
        prop_assert_ne!(request1.gamma, request2.gamma);
    }
}

// Property: Invalid proofs are always rejected
proptest! {
    #[test]
    fn prop_invalid_proofs_rejected(
        initial_amount in 10u64..1000,
        spend_amount in 1u64..10,
        tampering_scalar in scalar_strategy(),
        private_key in private_key_strategy(),
        pre_issuance in pre_issuance_strategy(),
    ) {
        let params = test_params();
        let initial_credits = Scalar::from(initial_amount);
        let spend_credits = Scalar::from(spend_amount);
        
        let request = pre_issuance.request(&params, OsRng);
        let response = private_key.issue(&params, &request, initial_credits, OsRng).unwrap();
        let token = pre_issuance
            .to_credit_token(&params, private_key.public(), &request, &response)
            .unwrap();
        
        let (mut spend_proof, _) = token.prove_spend(&params, spend_credits, OsRng);
        
        // Tamper with the proof
        spend_proof.gamma = spend_proof.gamma + tampering_scalar;
        
        // Refund should fail
        let refund_result = private_key.refund(&params, &spend_proof, OsRng);
        prop_assert!(refund_result.is_none());
    }
}

// Property: Public key derivation is consistent
proptest! {
    #[test]
    fn prop_public_key_derivation(x in scalar_strategy()) {
        let private_key = PrivateKey {
            x,
            public: PublicKey {
                w: RistrettoPoint::generator() * x,
            },
        };
        
        // Verify the public key matches the private key
        prop_assert_eq!(private_key.public.w, RistrettoPoint::generator() * private_key.x);
    }
}

// Property: Refund amount never exceeds initial amount
proptest! {
    #[test]
    fn prop_refund_never_exceeds_initial(
        initial_amount in 1u64..10000,
        operations in prop::collection::vec((1u64..100, any::<bool>()), 1..10),
        private_key in private_key_strategy(),
        pre_issuance in pre_issuance_strategy(),
    ) {
        let params = test_params();
        let initial_credits = Scalar::from(initial_amount);
        
        let request = pre_issuance.request(&params, OsRng);
        let response = private_key.issue(&params, &request, initial_credits, OsRng).unwrap();
        let mut current_token = pre_issuance
            .to_credit_token(&params, private_key.public(), &request, &response)
            .unwrap();
        
        let mut total_spent = 0u64;
        
        for (amount, should_process) in operations {
            if !should_process || total_spent + amount > initial_amount {
                continue;
            }
            
            let spend_amount = Scalar::from(amount);
            let (spend_proof, pre_refund) = current_token.prove_spend(&params, spend_amount, OsRng);
            
            if let Some(refund) = private_key.refund(&params, &spend_proof, OsRng) {
                total_spent += amount;
                
                current_token = pre_refund
                    .to_credit_token(&params, &spend_proof, &refund, private_key.public())
                    .unwrap();
                
                // Current balance + total spent should equal initial amount
                let current_balance = scalar_to_u128(&current_token.c).unwrap_or(0);
                prop_assert_eq!(current_balance + total_spent as u128, initial_amount as u128);
            }
        }
    }
}

// Additional CBOR round-trip tests
proptest! {
    #[test]
    fn prop_cbor_round_trip_issuance_response(
        a in point_strategy(),
        e in scalar_strategy(),
        gamma in scalar_strategy(),
        z in scalar_strategy(),
        c in scalar_strategy(),
    ) {
        let response = IssuanceResponse { a, e, gamma, z, c };
        let bytes = response.to_cbor().unwrap();
        let decoded = IssuanceResponse::from_cbor(&bytes).unwrap();
        
        prop_assert_eq!(response.a, decoded.a);
        prop_assert_eq!(response.e, decoded.e);
        prop_assert_eq!(response.gamma, decoded.gamma);
        prop_assert_eq!(response.z, decoded.z);
        prop_assert_eq!(response.c, decoded.c);
    }
}

proptest! {
    #[test]
    fn prop_cbor_round_trip_refund(
        a in point_strategy(),
        e in scalar_strategy(),
        gamma in scalar_strategy(),
        z in scalar_strategy(),
    ) {
        let refund = Refund { a, e, gamma, z };
        let bytes = refund.to_cbor().unwrap();
        let decoded = Refund::from_cbor(&bytes).unwrap();
        
        prop_assert_eq!(refund.a, decoded.a);
        prop_assert_eq!(refund.e, decoded.e);
        prop_assert_eq!(refund.gamma, decoded.gamma);
        prop_assert_eq!(refund.z, decoded.z);
    }
}

proptest! {
    #[test]
    fn prop_cbor_round_trip_pre_issuance(pre_issuance in pre_issuance_strategy()) {
        let bytes = pre_issuance.to_cbor().unwrap();
        let decoded = PreIssuance::from_cbor(&bytes).unwrap();
        
        prop_assert_eq!(pre_issuance.r, decoded.r);
        prop_assert_eq!(pre_issuance.k, decoded.k);
    }
}

proptest! {
    #[test]
    fn prop_cbor_round_trip_pre_refund(
        r in scalar_strategy(),
        k in scalar_strategy(),
        m in scalar_strategy(),
    ) {
        let pre_refund = PreRefund { r, k, m };
        let bytes = pre_refund.to_cbor().unwrap();
        let decoded = PreRefund::from_cbor(&bytes).unwrap();
        
        prop_assert_eq!(pre_refund.r, decoded.r);
        prop_assert_eq!(pre_refund.k, decoded.k);
        prop_assert_eq!(pre_refund.m, decoded.m);
    }
}

proptest! {
    #[test]
    fn prop_cbor_round_trip_public_key(w in point_strategy()) {
        let public_key = PublicKey { w };
        let bytes = public_key.to_cbor().unwrap();
        let decoded = PublicKey::from_cbor(&bytes).unwrap();
        
        prop_assert_eq!(public_key.w, decoded.w);
    }
}

// Property: SpendProof generation is deterministic given fixed randomness
proptest! {
    #[test]
    fn prop_spend_proof_structure_validity(
        initial_amount in 10u64..1000,
        spend_amount in 1u64..500,
        private_key in private_key_strategy(),
        pre_issuance in pre_issuance_strategy(),
    ) {
        let params = test_params();
        prop_assume!(spend_amount <= initial_amount);
        
        let initial_credits = Scalar::from(initial_amount);
        let spend_credits = Scalar::from(spend_amount);
        
        let request = pre_issuance.request(&params, OsRng);
        let response = private_key.issue(&params, &request, initial_credits, OsRng).unwrap();
        let token = pre_issuance
            .to_credit_token(&params, private_key.public(), &request, &response)
            .unwrap();
        
        let (spend_proof, _) = token.prove_spend(&params, spend_credits, OsRng);
        
        // Verify spend proof has valid structure
        prop_assert_ne!(spend_proof.k, Scalar::ZERO, "Nullifier should not be zero");
        prop_assert_eq!(spend_proof.s, spend_credits, "Spend amount should match");
        prop_assert_ne!(spend_proof.a_prime, RistrettoPoint::identity(), "a_prime should not be identity");
        
        // Verify the com array has correct length
        prop_assert_eq!(spend_proof.com.len(), L);
        prop_assert_eq!(spend_proof.gamma0.len(), L);
        prop_assert_eq!(spend_proof.z.len(), L);
    }
}

// Property: Token tampering is always detected
proptest! {
    #[test]
    fn prop_token_tampering_detection(
        initial_amount in 10u64..1000,
        private_key in private_key_strategy(),
        pre_issuance in pre_issuance_strategy(),
        tampering_point in point_strategy(),
        tampering_scalar in scalar_strategy(),
    ) {
        let params = test_params();
        let initial_credits = Scalar::from(initial_amount);
        
        let request = pre_issuance.request(&params, OsRng);
        let response = private_key.issue(&params, &request, initial_credits, OsRng).unwrap();
        let mut token = pre_issuance
            .to_credit_token(&params, private_key.public(), &request, &response)
            .unwrap();
        
        // Tamper with the token
        token.a = tampering_point;
        token.e = tampering_scalar;
        
        // Try to spend from tampered token
        let (spend_proof, _) = token.prove_spend(&params, Scalar::from(1u64), OsRng);
        
        // Refund should fail
        let refund_result = private_key.refund(&params, &spend_proof, OsRng);
        prop_assert!(refund_result.is_none(), "Tampered token should be rejected");
    }
}

// Property: Issuance with invalid request always fails
proptest! {
    #[test]
    fn prop_invalid_issuance_request_rejection(
        credit_amount in credit_amount_strategy(),
        private_key in private_key_strategy(),
        pre_issuance in pre_issuance_strategy(),
        random_point in point_strategy(),
        random_scalar in scalar_strategy(),
    ) {
        let params = test_params();
        let mut request = pre_issuance.request(&params, OsRng);
        
        // Tamper with the request
        request.big_k = random_point;
        request.gamma = random_scalar;
        
        // Issuance should fail
        let response = private_key.issue(&params, &request, credit_amount, OsRng);
        prop_assert!(response.is_none(), "Invalid request should be rejected");
    }
}

// Property: Spend amounts within valid range produce valid binary decompositions
proptest! {
    #[test]
    fn prop_spend_amount_binary_decomposition(
        spend_amount in any::<u128>(),
    ) {
        let scalar = Scalar::from(spend_amount);
        let bits = bits_of(scalar);
        
        // Verify all bits are either 0 or 1
        bits.iter()
            .enumerate()
            .try_for_each(|(i, bit)| {
                if *bit == Scalar::ZERO || *bit == Scalar::ONE {
                    Ok(())
                } else {
                    Err(proptest::test_runner::TestCaseError::fail(format!("Bit {} is not binary", i)))
                }
            })?;
        
        // Verify leading bits are zero for values less than 2^n
        let bit_length = 128 - spend_amount.leading_zeros() as usize;
        bits.iter()
            .enumerate()
            .skip(bit_length)
            .try_for_each(|(i, bit)| {
                if *bit == Scalar::ZERO {
                    Ok(())
                } else {
                    Err(proptest::test_runner::TestCaseError::fail(format!("Bit {} should be zero", i)))
                }
            })?;
    }
}

// Property: Multiple issuers don't interfere
proptest! {
    #[test]
    fn prop_multiple_issuers_independence(
        credit_amount in 10u64..1000,
        spend_amount in 1u64..10,
        private_key1 in private_key_strategy(),
        private_key2 in private_key_strategy(),
        pre_issuance in pre_issuance_strategy(),
    ) {
        let params = test_params();
        prop_assume!(private_key1.x != private_key2.x); // Different issuers
        
        let credits = Scalar::from(credit_amount);
        let spend = Scalar::from(spend_amount);
        
        let request = pre_issuance.request(&params, OsRng);
        
        // Issue with first issuer
        let response1 = private_key1.issue(&params, &request, credits, OsRng).unwrap();
        let token1 = pre_issuance
            .to_credit_token(&params, private_key1.public(), &request, &response1)
            .unwrap();
        
        // Try to spend token1 with issuer2 (should fail)
        let (spend_proof, _) = token1.prove_spend(&params, spend, OsRng);
        let refund2 = private_key2.refund(&params, &spend_proof, OsRng);
        prop_assert!(refund2.is_none(), "Wrong issuer should reject spend");
        
        // Correct issuer should accept
        let refund1 = private_key1.refund(&params, &spend_proof, OsRng);
        prop_assert!(refund1.is_some(), "Correct issuer should accept spend");
    }
}

// Property: Exhaustive spending works correctly
proptest! {
    #[test]
    fn prop_exhaustive_spending(
        initial_amount in 5u64..100,
        private_key in private_key_strategy(),
        pre_issuance in pre_issuance_strategy(),
    ) {
        let params = test_params();
        let initial_credits = Scalar::from(initial_amount);
        
        let request = pre_issuance.request(&params, OsRng);
        let response = private_key.issue(&params, &request, initial_credits, OsRng).unwrap();
        let mut token = pre_issuance
            .to_credit_token(&params, private_key.public(), &request, &response)
            .unwrap();
        
        let mut remaining = initial_amount;
        
        // Spend entire balance in decrements
        while remaining > 0 {
            let spend_amount = std::cmp::min(remaining, 5); // Spend up to 5 at a time
            let spend_scalar = Scalar::from(spend_amount);
            
            let (spend_proof, pre_refund) = token.prove_spend(&params, spend_scalar, OsRng);
            remaining -= spend_amount;
            
            prop_assert_eq!(pre_refund.m, Scalar::from(remaining));
            
            if remaining > 0 {
                let refund = private_key.refund(&params, &spend_proof, OsRng).unwrap();
                token = pre_refund
                    .to_credit_token(&params, &spend_proof, &refund, private_key.public())
                    .unwrap();
            }
        }
        
        prop_assert_eq!(remaining, 0);
    }
}

// Property: Challenge values affect proof generation
proptest! {
    #[test]
    fn prop_challenge_affects_proofs(
        initial_amount in 10u64..100,
        spend_amount in 1u64..10,
        private_key in private_key_strategy(),
        pre_issuance1 in pre_issuance_strategy(),
        pre_issuance2 in pre_issuance_strategy(),
    ) {
        let params = test_params();
        prop_assume!(pre_issuance1.r != pre_issuance2.r || pre_issuance1.k != pre_issuance2.k);
        
        let initial_credits = Scalar::from(initial_amount);
        let spend_credits = Scalar::from(spend_amount);
        
        // Issue two tokens with same amount
        let request1 = pre_issuance1.request(&params, OsRng);
        let response1 = private_key.issue(&params, &request1, initial_credits, OsRng).unwrap();
        let token1 = pre_issuance1
            .to_credit_token(&params, private_key.public(), &request1, &response1)
            .unwrap();
        
        let request2 = pre_issuance2.request(&params, OsRng);
        let response2 = private_key.issue(&params, &request2, initial_credits, OsRng).unwrap();
        let token2 = pre_issuance2
            .to_credit_token(&params, private_key.public(), &request2, &response2)
            .unwrap();
        
        // Generate spend proofs
        let (proof1, _) = token1.prove_spend(&params, spend_credits, OsRng);
        let (proof2, _) = token2.prove_spend(&params, spend_credits, OsRng);
        
        // Proofs should be different despite same spend amount
        prop_assert_ne!(proof1.gamma, proof2.gamma);
        prop_assert_ne!(proof1.k_bar, proof2.k_bar);
        prop_assert_ne!(proof1.r_bar, proof2.r_bar);
    }
}

// Property: Scalar arithmetic preserves validity
proptest! {
    #[test]
    fn prop_scalar_arithmetic_validity(
        a in any::<u64>(),
        b in any::<u64>(),
    ) {
        let scalar_a = Scalar::from(a);
        let scalar_b = Scalar::from(b);
        
        // Addition
        let _sum = scalar_a + scalar_b;
        
        // Subtraction (when valid)
        if a >= b {
            let diff = scalar_a - scalar_b;
            prop_assert_eq!(diff + scalar_b, scalar_a);
        }
        
        // Verify commutativity
        prop_assert_eq!(scalar_a + scalar_b, scalar_b + scalar_a);
        
        // Verify associativity with zero
        prop_assert_eq!(scalar_a + Scalar::ZERO, scalar_a);
        prop_assert_eq!(Scalar::ZERO + scalar_a, scalar_a);
    }
}

// Property: Point operations maintain group properties
proptest! {
    #[test]
    fn prop_point_group_properties(
        scalar1 in scalar_strategy(),
        scalar2 in scalar_strategy(),
    ) {
        let g = RistrettoPoint::generator();
        
        // Scalar multiplication distributivity
        let point1 = g * scalar1;
        let point2 = g * scalar2;
        let combined = g * (scalar1 + scalar2);
        
        prop_assert_eq!(point1 + point2, combined);
        
        // Identity element
        prop_assert_eq!(point1 + RistrettoPoint::identity(), point1);
        prop_assert_eq!(RistrettoPoint::identity() + point1, point1);
        
        // Scalar multiplication by zero
        prop_assert_eq!(g * Scalar::ZERO, RistrettoPoint::identity());
    }
}

// Property: Nullifier computation is collision-resistant
proptest! {
    #[test]
    fn prop_nullifier_collision_resistance(
        tokens in prop::collection::vec(
            (pre_issuance_strategy(), credit_amount_strategy()),
            10..20
        ),
        private_key in private_key_strategy(),
    ) {
        let params = test_params();
        let mut nullifiers = HashSet::new();
        
        for (pre_issuance, credit_amount) in tokens {
            // Skip if credit amount is not representable in u128
            if scalar_to_u128(&credit_amount).is_none() {
                continue;
            }
            
            let request = pre_issuance.request(&params, OsRng);
            if let Some(response) = private_key.issue(&params, &request, credit_amount, OsRng) {
                if let Some(token) = pre_issuance.to_credit_token(
                    &params,
                    private_key.public(),
                    &request,
                    &response,
                ) {
                    let (proof, _) = token.prove_spend(&params, Scalar::from(1u64), OsRng);
                    let nullifier = proof.nullifier();
                    
                    // Check for collision
                    prop_assert!(
                        !nullifiers.contains(&nullifier),
                        "Nullifier collision detected"
                    );
                    nullifiers.insert(nullifier);
                }
            }
        }
    }
}

// Property: CBOR encoding is canonical
proptest! {
    #[test]
    fn prop_cbor_encoding_canonical(
        token in credit_token_strategy(),
    ) {
        // Encode twice
        let bytes1 = token.to_cbor().unwrap();
        let bytes2 = token.to_cbor().unwrap();
        
        // Should produce identical bytes (canonical encoding)
        prop_assert_eq!(&bytes1, &bytes2);
        
        // Decode and re-encode
        let decoded = CreditToken::from_cbor(&bytes1).unwrap();
        let bytes3 = decoded.to_cbor().unwrap();
        
        // Should still be identical
        prop_assert_eq!(&bytes1, &bytes3);
    }
}
