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
    for _i in 0..10 {
        let private_key = PrivateKey::random(OsRng);
        let preissuance = PreIssuance::random(OsRng);
        let issuance_request = preissuance.request(OsRng);
        let issuance_response = private_key
            .issue(&issuance_request, Scalar::from(40u64), OsRng)
            .unwrap();
        let credit_token1 = preissuance
            .to_credit_token(private_key.public(), &issuance_request, &issuance_response)
            .unwrap();
        let charge = Scalar::from(20u64);
        let (spend_proof, prerefund) = credit_token1.prove_spend(charge, OsRng);
        let refund = private_key.refund(&spend_proof, OsRng).unwrap();
        let credit_token2 = prerefund
            .to_credit_token(&spend_proof, &refund, private_key.public())
            .unwrap();
        let charge = Scalar::from(20u64);
        let (spend_proof, prerefund) = credit_token2.prove_spend(charge, OsRng);
        let refund = private_key.refund(&spend_proof, OsRng).unwrap();
        let _credit_token3 = prerefund
            .to_credit_token(&spend_proof, &refund, private_key.public())
            .unwrap();
    }
}

#[test]
fn double_spend_prevention() {
    // Initialize nullifier database
    let mut nullifier_db = NullifierDb::new();
    
    // Setup issuer and client
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let issuance_request = preissuance.request(OsRng);
    let issuance_response = private_key
        .issue(&issuance_request, Scalar::from(100u64), OsRng)
        .unwrap();
    let credit_token = preissuance
        .to_credit_token(private_key.public(), &issuance_request, &issuance_response)
        .unwrap();
    
    // First spend is successful
    let charge1 = Scalar::from(30u64);
    let (spend_proof1, prerefund1) = credit_token.prove_spend(charge1, OsRng);
    
    // Verify nullifier isn't already spent
    let nullifier = spend_proof1.nullifier();
    assert!(!nullifier_db.is_spent(&nullifier), "Nullifier should not be spent yet");
    
    // Process refund
    let refund1 = private_key.refund(&spend_proof1, OsRng).unwrap();
    
    // Record nullifier as spent
    nullifier_db.record_spent(&nullifier);
    
    // Create new token from refund
    let new_token = prerefund1
        .to_credit_token(&spend_proof1, &refund1, private_key.public())
        .unwrap();
    
    // Attempt to use the same original token (double-spend attempt)
    let charge2 = Scalar::from(40u64);
    let (spend_proof2, _) = credit_token.prove_spend(charge2, OsRng);
    
    // Check nullifier - should detect double spend
    let nullifier2 = spend_proof2.nullifier();
    assert!(nullifier_db.is_spent(&nullifier2), "Double-spend not detected");
    
    // Verify we can spend from the new token
    let charge3 = Scalar::from(20u64);
    let (spend_proof3, _) = new_token.prove_spend(charge3, OsRng);
    let nullifier3 = spend_proof3.nullifier();
    
    // This is a different nullifier, should not be detected as spent
    assert!(!nullifier_db.is_spent(&nullifier3), "New token spend incorrectly marked as double-spend");
}

#[test]
fn spend_exact_balance() {
    // Test spending the exact balance amount
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let issuance_request = preissuance.request(OsRng);
    
    let credit_amount = Scalar::from(50u64);
    let issuance_response = private_key
        .issue(&issuance_request, credit_amount, OsRng)
        .unwrap();
    let credit_token = preissuance
        .to_credit_token(private_key.public(), &issuance_request, &issuance_response)
        .unwrap();
    
    // Spend the exact balance amount
    let (spend_proof, prerefund) = credit_token.prove_spend(credit_amount, OsRng);
    
    // Verify the refund amount is zero
    assert_eq!(prerefund.m, Scalar::ZERO, "Remaining balance should be zero");
    
    // Verify the refund still processes correctly
    let refund = private_key.refund(&spend_proof, OsRng).unwrap();
    let new_token = prerefund
        .to_credit_token(&spend_proof, &refund, private_key.public())
        .unwrap();
    
    // New token should have zero balance
    assert_eq!(new_token.c, Scalar::ZERO, "New token should have zero balance");
}

#[test]
fn sequential_spends() {
    let mut nullifier_db = NullifierDb::new();
    
    // Issue a token with a large balance
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let issuance_request = preissuance.request(OsRng);
    let initial_amount = Scalar::from(100u64);
    let issuance_response = private_key
        .issue(&issuance_request, initial_amount, OsRng)
        .unwrap();
    let mut current_token = preissuance
        .to_credit_token(private_key.public(), &issuance_request, &issuance_response)
        .unwrap();
    
    // Perform 5 sequential spends, each spending 10 credits
    let spend_amount = Scalar::from(10u64);
    let mut remaining = 100;
    
    for i in 1..=5 {
        // Spend some credits
        let (spend_proof, prerefund) = current_token.prove_spend(spend_amount, OsRng);
        remaining -= 10;
        
        // Check that the remaining amount is correct
        assert_eq!(
            prerefund.m, 
            Scalar::from(remaining as u64), 
            "Remaining balance incorrect after spend {}", 
            i
        );
        
        // Record the nullifier
        let nullifier = spend_proof.nullifier();
        assert!(!nullifier_db.is_spent(&nullifier), "Nullifier already spent in iteration {}", i);
        nullifier_db.record_spent(&nullifier);
        
        // Get refund and create new token
        let refund = private_key.refund(&spend_proof, OsRng).unwrap();
        current_token = prerefund
            .to_credit_token(&spend_proof, &refund, private_key.public())
            .unwrap();
        
        // Verify the new token has the correct balance
        assert_eq!(
            current_token.c, 
            Scalar::from(remaining as u64), 
            "New token has incorrect balance after spend {}", 
            i
        );
    }
    
    // Verify final remaining balance is 50
    assert_eq!(current_token.c, Scalar::from(50u64), "Final balance incorrect");
}

#[test]
fn attempt_overspend() {
    // Create a token with 20 credits
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let issuance_request = preissuance.request(OsRng);
    let credit_amount = Scalar::from(20u64);
    let issuance_response = private_key
        .issue(&issuance_request, credit_amount, OsRng)
        .unwrap();
    let credit_token = preissuance
        .to_credit_token(private_key.public(), &issuance_request, &issuance_response)
        .unwrap();
    
    // Try to spend more than available (30 > 20)
    let overspend_amount = Scalar::from(30u64);
    let (spend_proof, _) = credit_token.prove_spend(overspend_amount, OsRng);
    
    // The refund verification should fail when the issuer checks it
    let refund_result = private_key.refund(&spend_proof, OsRng);
    
    // The refund should be None since the proof is invalid
    assert!(refund_result.is_none(), "Overspend should have been rejected");
}

#[test]
fn zero_spend_scenario() {
    // Create a token with 20 credits
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let issuance_request = preissuance.request(OsRng);
    let credit_amount = Scalar::from(20u64);
    let issuance_response = private_key
        .issue(&issuance_request, credit_amount, OsRng)
        .unwrap();
    let credit_token = preissuance
        .to_credit_token(private_key.public(), &issuance_request, &issuance_response)
        .unwrap();
    
    // Spend zero credits
    let zero_spend = Scalar::from(0u64);
    let (spend_proof, prerefund) = credit_token.prove_spend(zero_spend, OsRng);
    
    // The refund should process successfully
    let refund = private_key.refund(&spend_proof, OsRng).unwrap();
    
    // Remaining balance should still be 20
    assert_eq!(prerefund.m, credit_amount, "Remaining balance should be unchanged");
    
    // Create new token
    let new_token = prerefund
        .to_credit_token(&spend_proof, &refund, private_key.public())
        .unwrap();
    
    // New token should have the same balance
    assert_eq!(new_token.c, credit_amount, "New token should have the original amount");
}

#[test]
fn multiple_tokens_with_same_issuer() {
    let mut nullifier_db = NullifierDb::new();
    
    // Single issuer
    let private_key = PrivateKey::random(OsRng);
    
    // Create two separate tokens for two different clients
    let preissuance1 = PreIssuance::random(OsRng);
    let request1 = preissuance1.request(OsRng);
    let response1 = private_key.issue(&request1, Scalar::from(50u64), OsRng).unwrap();
    let token1 = preissuance1.to_credit_token(private_key.public(), &request1, &response1).unwrap();
    
    let preissuance2 = PreIssuance::random(OsRng);
    let request2 = preissuance2.request(OsRng);
    let response2 = private_key.issue(&request2, Scalar::from(30u64), OsRng).unwrap();
    let token2 = preissuance2.to_credit_token(private_key.public(), &request2, &response2).unwrap();
    
    // Both clients spend from their tokens
    let (spend_proof1, prerefund1) = token1.prove_spend(Scalar::from(20u64), OsRng);
    let (spend_proof2, prerefund2) = token2.prove_spend(Scalar::from(15u64), OsRng);
    
    // Get the nullifiers
    let nullifier1 = spend_proof1.nullifier();
    let nullifier2 = spend_proof2.nullifier();
    
    // Nullifiers should be different
    assert_ne!(nullifier1, nullifier2, "Tokens should have different nullifiers");
    
    // Record both spends
    nullifier_db.record_spent(&nullifier1);
    nullifier_db.record_spent(&nullifier2);
    
    // Process refunds
    let refund1 = private_key.refund(&spend_proof1, OsRng).unwrap();
    let refund2 = private_key.refund(&spend_proof2, OsRng).unwrap();
    
    // Create new tokens
    let new_token1 = prerefund1.to_credit_token(&spend_proof1, &refund1, private_key.public()).unwrap();
    let new_token2 = prerefund2.to_credit_token(&spend_proof2, &refund2, private_key.public()).unwrap();
    
    // Check remaining balances
    assert_eq!(new_token1.c, Scalar::from(30u64), "First token should have 30 credits remaining");
    assert_eq!(new_token2.c, Scalar::from(15u64), "Second token should have 15 credits remaining");
}

#[test]
fn bits_of_() {
    let x = Scalar::from(2u64.pow(L as u32) - 1);
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
    let x = Scalar::from(0b10101010101010101010101010101010u64);
    let bits = crate::bits_of(x);
    for i in 0..L {
        if i % 2 == 1 {
            assert_eq!(bits[i], Scalar::ONE);
        } else {
            assert_eq!(bits[i], Scalar::ZERO);
        }
    }
    let x = Scalar::from(0b01010101010101010101010101010101u64);
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
    
    // Create a valid preissuance state
    let preissuance = PreIssuance::random(OsRng);
    
    // Create a valid request
    let valid_request = preissuance.request(OsRng);
    
    // Tamper with the request by modifying the k_bar value
    let tampered_request = IssuanceRequest {
        big_k: valid_request.big_k,
        gamma: valid_request.gamma,
        k_bar: valid_request.k_bar + Scalar::ONE, // Modify the k_bar value
        r_bar: valid_request.r_bar,
    };
    
    // The issuer should reject the tampered request
    let issuance_response = private_key.issue(&tampered_request, Scalar::from(20u64), OsRng);
    assert!(issuance_response.is_none(), "Tampered request should be rejected");
    
    // The original request should be accepted
    let issuance_response = private_key.issue(&valid_request, Scalar::from(20u64), OsRng);
    assert!(issuance_response.is_some(), "Valid request should be accepted");
}

#[test]
fn invalid_proof_verification() {
    // Create a private key and token
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let request = preissuance.request(OsRng);
    let response = private_key.issue(&request, Scalar::from(50u64), OsRng).unwrap();
    let token = preissuance.to_credit_token(private_key.public(), &request, &response).unwrap();
    
    // Create a valid spend proof
    let (spend_proof, _) = token.prove_spend(Scalar::from(20u64), OsRng);
    
    // Tamper with the proof by modifying the amount
    let tampered_proof = SpendProof {
        s: Scalar::from(30u64), // Changed from 20 to 30
        ..spend_proof
    };
    
    // The issuer should reject the tampered proof
    let refund_result = private_key.refund(&tampered_proof, OsRng);
    assert!(refund_result.is_none(), "Tampered proof should be rejected");
}

#[test]
fn large_amount_issuance() {
    // Test with a very large credit amount (but still within the L-bit range)
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let request = preissuance.request(OsRng);
    
    // Create a large amount, close to the maximum representable value
    let large_amount = Scalar::from(2u64.pow(L as u32 - 1)); // 2^31
    
    let response = private_key.issue(&request, large_amount, OsRng).unwrap();
    let token = preissuance.to_credit_token(private_key.public(), &request, &response).unwrap();
    
    // Spend a portion of the large amount
    let spend_amount = Scalar::from(1_000_000u64); // Spend 1 million credits
    let (spend_proof, prerefund) = token.prove_spend(spend_amount, OsRng);
    
    // The remaining amount should be correct
    let expected_remaining = large_amount - spend_amount;
    assert_eq!(prerefund.m, expected_remaining, "Remaining balance incorrect");
    
    // The refund should process correctly
    let refund = private_key.refund(&spend_proof, OsRng).unwrap();
    let new_token = prerefund.to_credit_token(&spend_proof, &refund, private_key.public()).unwrap();
    
    // The new token should have the expected balance
    assert_eq!(new_token.c, expected_remaining, "New token balance incorrect");
}

#[test]
fn invalid_token_verification() {
    // Create a private key and token
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let request = preissuance.request(OsRng);
    let response = private_key.issue(&request, Scalar::from(50u64), OsRng).unwrap();
    
    // Tamper with the response
    let tampered_response = IssuanceResponse {
        gamma: response.gamma,
        a: response.a,
        e: response.e + Scalar::ONE, // Modify the e value
        z: response.z,
        c: response.c,
    };
    
    // The client should reject the tampered response
    let token_result = preissuance.to_credit_token(
        private_key.public(),
        &request,
        &tampered_response
    );
    assert!(token_result.is_none(), "Tampered response should be rejected");
    
    // The original response should be accepted
    let token_result = preissuance.to_credit_token(
        private_key.public(),
        &request,
        &response
    );
    assert!(token_result.is_some(), "Valid response should be accepted");
}

#[test]
fn transcript_add_elements_test() {
    use curve25519_dalek::RistrettoPoint;
    
    // Create points to add to the transcript
    let point1 = RistrettoPoint::generator();
    let point2 = RistrettoPoint::generator() * Scalar::from(2u64);
    let point3 = RistrettoPoint::generator() * Scalar::from(3u64);
    
    // Create a transcript and add elements using add_elements
    let mut transcript1 = Transcript::new(b"test");
    transcript1.add_elements([&point1, &point2, &point3].into_iter());
    let challenge1 = transcript1.challenge();
    
    // Create another transcript and add the same elements one by one
    let mut transcript2 = Transcript::new(b"test");
    transcript2.add_element(&point1);
    transcript2.add_element(&point2);
    transcript2.add_element(&point3);
    let challenge2 = transcript2.challenge();
    
    // The challenges should be identical
    assert_eq!(challenge1, challenge2, "add_elements should produce the same result as multiple add_element calls");
}

#[test]
fn tampered_refund_verification() {
    // Setup
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let request = preissuance.request(OsRng);
    let response = private_key.issue(&request, Scalar::from(50u64), OsRng).unwrap();
    let token = preissuance.to_credit_token(private_key.public(), &request, &response).unwrap();
    
    // Create a valid spend
    let spend_amount = Scalar::from(20u64);
    let (spend_proof, prerefund) = token.prove_spend(spend_amount, OsRng);
    
    // Get a valid refund
    let refund = private_key.refund(&spend_proof, OsRng).unwrap();
    
    // Tamper with the refund
    let tampered_refund = Refund {
        a: refund.a,
        e: refund.e + Scalar::ONE, // Modify the e value
        gamma: refund.gamma,
        z: refund.z,
    };
    
    // The client should reject the tampered refund
    let new_token_result = prerefund.to_credit_token(&spend_proof, &tampered_refund, private_key.public());
    assert!(new_token_result.is_none(), "Tampered refund should be rejected");
    
    // The original refund should be accepted
    let new_token_result = prerefund.to_credit_token(&spend_proof, &refund, private_key.public());
    assert!(new_token_result.is_some(), "Valid refund should be accepted");
}

#[test]
fn zero_e_signature_attack() {
    // Test if a zero e value in the signature can be exploited
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let request = preissuance.request(OsRng);
    let response = private_key.issue(&request, Scalar::from(20u64), OsRng).unwrap();
    
    // Create a tampered response with e = 0
    let tampered_response = IssuanceResponse {
        a: response.a,
        e: Scalar::ZERO, // Set e to zero
        gamma: response.gamma,
        z: response.z,
        c: response.c,
    };
    
    // The client should reject this (though the actual signature verification may fail in different ways)
    let token_result = preissuance.to_credit_token(
        private_key.public(),
        &request,
        &tampered_response
    );
    assert!(token_result.is_none(), "Zero e value should be rejected");
}

#[test]
fn spend_with_identity_a_prime() {
    // Create a token
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let request = preissuance.request(OsRng);
    let response = private_key.issue(&request, Scalar::from(20u64), OsRng).unwrap();
    let token = preissuance.to_credit_token(private_key.public(), &request, &response).unwrap();
    
    // Create a valid spend proof
    let (mut spend_proof, _) = token.prove_spend(Scalar::from(10u64), OsRng);
    
    // Tamper with the proof - set a_prime to identity
    spend_proof.a_prime = RistrettoPoint::identity();
    
    // The issuer should reject this proof
    let refund_result = private_key.refund(&spend_proof, OsRng);
    assert!(refund_result.is_none(), "Spend proof with identity a_prime should be rejected");
}

#[test]
fn token_with_zero_credit() {
    // Create a token with zero credits
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let request = preissuance.request(OsRng);
    let zero_amount = Scalar::ZERO;
    let response = private_key.issue(&request, zero_amount, OsRng).unwrap();
    let token = preissuance.to_credit_token(private_key.public(), &request, &response).unwrap();
    
    // Token should have zero balance
    assert_eq!(token.c, Scalar::ZERO, "Token should have zero balance");
    
    // Attempting to spend from this token should fail
    let spend_amount = Scalar::from(10u64);
    let (spend_proof, _) = token.prove_spend(spend_amount, OsRng);
    let refund_result = private_key.refund(&spend_proof, OsRng);
    assert!(refund_result.is_none(), "Spending from a zero-balance token should fail");
    
    // But spending zero from it should work
    let zero_spend = Scalar::ZERO;
    let (spend_proof, prerefund) = token.prove_spend(zero_spend, OsRng);
    let refund = private_key.refund(&spend_proof, OsRng).unwrap();
    let new_token = prerefund.to_credit_token(&spend_proof, &refund, private_key.public()).unwrap();
    assert_eq!(new_token.c, Scalar::ZERO, "New token should still have zero balance");
}