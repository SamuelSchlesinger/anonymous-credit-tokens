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
    for i in 0..L {
        assert_eq!(bits[i], Scalar::ONE);
    }
    let x = Scalar::from(0u64);
    let bits = crate::bits_of(x);
    for i in 0..L {
        assert_eq!(bits[i], Scalar::ZERO);
    }
    let x = Scalar::from(0b001u64);
    let bits = crate::bits_of(x);
    for i in 0..L {
        if i == 0 {
            assert_eq!(bits[i], Scalar::ONE);
        } else {
            assert_eq!(bits[i], Scalar::ZERO);
        }
    }
    let x = Scalar::from(0b100000000u64);
    let bits = crate::bits_of(x);
    for i in 0..L {
        if i == 8 {
            assert_eq!(bits[i], Scalar::ONE);
        } else {
            assert_eq!(bits[i], Scalar::ZERO);
        }
    }
    let x = Scalar::from(7u64);
    let bits = crate::bits_of(x);
    for i in 0..L {
        if i <= 2 {
            assert_eq!(bits[i], Scalar::ONE);
        } else {
            assert_eq!(bits[i], Scalar::ZERO);
        }
    }
    let x = Scalar::from(0b10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010u128);
    let bits = crate::bits_of(x);
    for i in 0..L {
        if i % 2 == 1 {
            assert_eq!(bits[i], Scalar::ONE);
        } else {
            assert_eq!(bits[i], Scalar::ZERO);
        }
    }
    let x = Scalar::from(0b01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101u128);
    let bits = crate::bits_of(x);
    for i in 0..L {
        if i % 2 == 0 {
            assert_eq!(bits[i], Scalar::ONE);
        } else {
            assert_eq!(bits[i], Scalar::ZERO);
        }
    }
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
