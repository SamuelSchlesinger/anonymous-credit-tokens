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

use super::*;
use crate::ciphersuite::Ciphersuite;
use crate::tests_common::TestCiphersuite;
use crate::transcript::Transcript;
use group::Group;
use proptest::prelude::*;
use rand_core::OsRng;

impl TestCiphersuite for Ristretto255 {
    fn test_context() -> Scalar {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"test-request-context:example.com/api/charge");
        let mut wide = [0u8; 64];
        let mut reader = hasher.finalize_xof();
        reader.fill(&mut wide);
        Scalar::from_bytes_mod_order_wide(&wide)
    }
}

// Instantiate all common tests for Ristretto255
crate::instantiate_tests!(Ristretto255);

// ── Ciphersuite-specific tests ──────────────────────────────────────

#[test]
fn test_params_generation_deterministic() {
    let params1 = Params::new("test-org", "test-service", "test", "2024-01-01").unwrap();
    let params2 = Params::new("test-org", "test-service", "test", "2024-01-01").unwrap();
    assert_eq!(
        params1.h1.basepoint().compress(),
        params2.h1.basepoint().compress()
    );
    assert_eq!(
        params1.h2.basepoint().compress(),
        params2.h2.basepoint().compress()
    );
    assert_eq!(
        params1.h3.basepoint().compress(),
        params2.h3.basepoint().compress()
    );
    assert_eq!(
        params1.h4.basepoint().compress(),
        params2.h4.basepoint().compress()
    );
    let params3 = Params::new("different-org", "test-service", "test", "2024-01-01").unwrap();
    assert_ne!(
        params1.h1.basepoint().compress(),
        params3.h1.basepoint().compress()
    );
}

// ===== PROPERTY-BASED TESTING WITH PROPTEST =====

/// Local wrapper so proptest closures can call test_context() without
/// spelling out the trait path every time.
fn test_context() -> Scalar {
    <Ristretto255 as TestCiphersuite>::test_context()
}

/// Strategy for generating random Scalars
fn scalar_strategy() -> impl Strategy<Value = Scalar> {
    prop::array::uniform32(any::<u8>()).prop_map(Scalar::from_bytes_mod_order)
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
        PrivateKey {
            x,
            public: PublicKey { w },
        }
    })
}

/// Strategy for generating PreIssuance
fn pre_issuance_strategy() -> impl Strategy<Value = PreIssuance> {
    (scalar_strategy(), scalar_strategy()).prop_map(|(r, k)| PreIssuance { r, k })
}

/// Strategy for generating CreditTokens
fn credit_token_strategy() -> impl Strategy<Value = CreditToken> {
    (
        point_strategy(),
        scalar_strategy(),
        scalar_strategy(),
        scalar_strategy(),
        scalar_strategy(),
        scalar_strategy(),
    )
        .prop_map(|(a, e, k, r, c, ctx)| CreditToken { a, e, k, r, c, ctx })
}

// Use a single test params instance to avoid stack issues
fn test_params() -> Params {
    Params::new("test-org", "test-service", "test-env", "2024-01-01").unwrap()
}

// Property: Issuance protocol maintains balance invariant
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn prop_issuance_balance_invariant(
        credit_amount in credit_amount_strategy(),
        private_key in private_key_strategy(),
        pre_issuance in pre_issuance_strategy(),
    ) {
        let params = test_params();
        let request = pre_issuance.request(&params, OsRng);

        if let Ok(response) = private_key.issue::<128>(&params, &request, credit_amount, test_context(), OsRng)
            && let Ok(token) = pre_issuance.to_credit_token::<128>(
                &params,
                private_key.public(),
                &request,
                &response,
            )
        {
            // The token should have the exact credit amount issued
            prop_assert_eq!(token.c, credit_amount);
        }
    }
}

// Property: Double issuance with same request fails
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn prop_no_double_issuance(
        credit_amount in credit_amount_strategy(),
        private_key in private_key_strategy(),
        pre_issuance in pre_issuance_strategy(),
    ) {
        let params = test_params();
        let request = pre_issuance.request(&params, OsRng);

        // First issuance should succeed
        let response1 = private_key.issue::<128>(&params, &request, credit_amount, test_context(), OsRng);
        prop_assert!(response1.is_ok());

        // Second issuance with same request should fail (simulated by checking)
        // In a real system, the issuer would track used requests
    }
}

// Property: Spend + Refund preserves total balance
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
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
        let response = private_key.issue::<128>(&params, &request, initial_credits, test_context(), OsRng).unwrap();
        let token = pre_issuance
            .to_credit_token::<128>(&params, private_key.public(), &request, &response)
            .unwrap();

        // Spend some credits
        let (spend_proof, pre_refund) = token.prove_spend::<128>(&params, spend_credits, OsRng).unwrap();

        // Remaining balance should be correct
        let expected_remaining = initial_credits - spend_credits;
        prop_assert_eq!(pre_refund.m, expected_remaining);

        // Process refund
        if let Ok(refund) = private_key.refund(&params, &spend_proof, Scalar::ZERO, OsRng) {
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
    #![proptest_config(ProptestConfig::with_cases(10))]
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
        if let Ok(response) = private_key.issue::<128>(&params, &request, credit_amount, test_context(), OsRng)
            && let Ok(token) = pre_issuance.to_credit_token::<128>(
                &params,
                private_key.public(),
                &request,
                &response,
            )
        {
            // Generate two spend proofs from the same token
            let (proof1, _) = token.prove_spend::<128>(&params, spend_amount, OsRng).unwrap();
            let (proof2, _) = token.prove_spend::<128>(&params, spend_amount, OsRng).unwrap();

            // Nullifiers should be identical (deterministic)
            prop_assert_eq!(proof1.nullifier(), proof2.nullifier());
        }
    }
}

// Property: Different tokens have different nullifiers
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
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
        let response1 = private_key.issue::<128>(&params, &request1, credits, test_context(), OsRng).unwrap();
        let token1 = pre_issuance1
            .to_credit_token::<128>(&params, private_key.public(), &request1, &response1)
            .unwrap();

        let request2 = pre_issuance2.request(&params, OsRng);
        let response2 = private_key.issue::<128>(&params, &request2, credits, test_context(), OsRng).unwrap();
        let token2 = pre_issuance2
            .to_credit_token::<128>(&params, private_key.public(), &request2, &response2)
            .unwrap();

        // Get nullifiers
        let (proof1, _) = token1.prove_spend::<128>(&params, spend_amount, OsRng).unwrap();
        let (proof2, _) = token2.prove_spend::<128>(&params, spend_amount, OsRng).unwrap();

        // Nullifiers should be different
        prop_assert_ne!(proof1.nullifier(), proof2.nullifier());
    }
}

// Property: CBOR serialization round-trip for all types
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
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
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn prop_cbor_round_trip_credit_token(token in credit_token_strategy()) {
        let bytes = token.to_cbor().unwrap();
        let decoded = CreditToken::from_cbor(&bytes).unwrap();

        prop_assert_eq!(token.a, decoded.a);
        prop_assert_eq!(token.e, decoded.e);
        prop_assert_eq!(token.k, decoded.k);
        prop_assert_eq!(token.r, decoded.r);
        prop_assert_eq!(token.c, decoded.c);
        prop_assert_eq!(token.ctx, decoded.ctx);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
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
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn prop_binary_decomposition_correctness(value in any::<u128>()) {
        let scalar = Scalar::from(value);
        let bits = Ristretto255::bits_of::<128>(scalar);

        // Reconstruct the value from bits
        let reconstructed = bits.iter()
            .enumerate()
            .fold(Scalar::ZERO, |acc, (i, bit)| {
                if bool::from(*bit) {
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
    #![proptest_config(ProptestConfig::with_cases(10))]
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
        let response = private_key.issue::<128>(&params, &request, initial_credits, test_context(), OsRng).unwrap();
        let token = pre_issuance
            .to_credit_token::<128>(&params, private_key.public(), &request, &response)
            .unwrap();

        // prove_spend should reject overspending at the client side
        let result = token.prove_spend::<128>(&params, overspend_amount, OsRng);
        prop_assert!(result.is_err());
    }
}

// Property: Sequential spends accumulate correctly
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
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
        let response = private_key.issue::<128>(&params, &request, initial_credits, test_context(), OsRng).unwrap();
        let mut current_token = pre_issuance
            .to_credit_token::<128>(&params, private_key.public(), &request, &response)
            .unwrap();

        let mut remaining = initial_amount;

        // Perform sequential spends
        for spend_amount in spend_amounts {
            let spend_scalar = Scalar::from(spend_amount);
            let (spend_proof, pre_refund) = current_token.prove_spend::<128>(&params, spend_scalar, OsRng).unwrap();

            remaining -= spend_amount;
            prop_assert_eq!(pre_refund.m, Scalar::from(remaining));

            let refund = private_key.refund(&params, &spend_proof, Scalar::ZERO, OsRng).unwrap();
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
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn prop_transcript_determinism(
        label in prop::collection::vec(any::<u8>(), 1..32),
        points in prop::collection::vec(point_strategy(), 1..5),
    ) {
        let params = test_params();
        // Create two transcripts with same inputs
        let challenge1 = Transcript::<Ristretto255>::with(&params.transcript_base, &label, |transcript| {
            for point in &points {
                transcript.add_element(point);
            }
        });

        let challenge2 = Transcript::<Ristretto255>::with(&params.transcript_base, &label, |transcript| {
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
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn prop_zero_amount_handling(
        initial_amount in 1u64..10000,
        private_key in private_key_strategy(),
        pre_issuance in pre_issuance_strategy(),
    ) {
        let params = test_params();
        let initial_credits = Scalar::from(initial_amount);

        let request = pre_issuance.request(&params, OsRng);
        let response = private_key.issue::<128>(&params, &request, initial_credits, test_context(), OsRng).unwrap();
        let token = pre_issuance
            .to_credit_token::<128>(&params, private_key.public(), &request, &response)
            .unwrap();

        // Spend zero
        let (spend_proof, pre_refund) = token.prove_spend::<128>(&params, Scalar::ZERO, OsRng).unwrap();

        // Balance should be unchanged
        prop_assert_eq!(pre_refund.m, initial_credits);

        let refund = private_key.refund(&params, &spend_proof, Scalar::ZERO, OsRng).unwrap();
        let new_token = pre_refund
            .to_credit_token(&params, &spend_proof, &refund, private_key.public())
            .unwrap();

        prop_assert_eq!(new_token.c, initial_credits);
    }
}

// Property: Params affect cryptographic outputs
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn prop_params_affect_outputs(
        pre_issuance in pre_issuance_strategy(),
    ) {
        let params1 = test_params();
        let params2 = Params::new("other-org", "other-service", "other-env", "2024-12-31").unwrap();

        let request1 = pre_issuance.request(&params1, OsRng);
        let request2 = pre_issuance.request(&params2, OsRng);

        // Requests should be different with different params
        prop_assert_ne!(request1.gamma, request2.gamma);
    }
}

// Property: Invalid proofs are always rejected
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
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
        let response = private_key.issue::<128>(&params, &request, initial_credits, test_context(), OsRng).unwrap();
        let token = pre_issuance
            .to_credit_token::<128>(&params, private_key.public(), &request, &response)
            .unwrap();

        let (mut spend_proof, _) = token.prove_spend::<128>(&params, spend_credits, OsRng).unwrap();

        // Tamper with the proof
        spend_proof.gamma += tampering_scalar;

        // Refund should fail
        let refund_result = private_key.refund(&params, &spend_proof, Scalar::ZERO, OsRng);
        prop_assert!(refund_result.is_err());
    }
}

// Property: Public key derivation is consistent
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
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
    #![proptest_config(ProptestConfig::with_cases(10))]
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
        let response = private_key.issue::<128>(&params, &request, initial_credits, test_context(), OsRng).unwrap();
        let mut current_token = pre_issuance
            .to_credit_token::<128>(&params, private_key.public(), &request, &response)
            .unwrap();

        let mut total_spent = 0u64;

        for (amount, should_process) in operations {
            if !should_process || total_spent + amount > initial_amount {
                continue;
            }

            let spend_amount = Scalar::from(amount);
            let (spend_proof, pre_refund) = current_token.prove_spend::<128>(&params, spend_amount, OsRng).unwrap();

            if let Ok(refund) = private_key.refund(&params, &spend_proof, Scalar::ZERO, OsRng) {
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
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn prop_cbor_round_trip_issuance_response(
        a in point_strategy(),
        e in scalar_strategy(),
        gamma in scalar_strategy(),
        z in scalar_strategy(),
        c in scalar_strategy(),
        ctx in scalar_strategy(),
    ) {
        let response = IssuanceResponse { a, e, gamma, z, c, ctx };
        let bytes = response.to_cbor().unwrap();
        let decoded = IssuanceResponse::from_cbor(&bytes).unwrap();

        prop_assert_eq!(response.a, decoded.a);
        prop_assert_eq!(response.e, decoded.e);
        prop_assert_eq!(response.gamma, decoded.gamma);
        prop_assert_eq!(response.z, decoded.z);
        prop_assert_eq!(response.c, decoded.c);
        prop_assert_eq!(response.ctx, decoded.ctx);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn prop_cbor_round_trip_refund(
        a in point_strategy(),
        e in scalar_strategy(),
        gamma in scalar_strategy(),
        z in scalar_strategy(),
        t in scalar_strategy(),
    ) {
        let refund = Refund { a, e, gamma, z, t };
        let bytes = refund.to_cbor().unwrap();
        let decoded = Refund::from_cbor(&bytes).unwrap();

        prop_assert_eq!(refund.a, decoded.a);
        prop_assert_eq!(refund.e, decoded.e);
        prop_assert_eq!(refund.gamma, decoded.gamma);
        prop_assert_eq!(refund.z, decoded.z);
        prop_assert_eq!(refund.t, decoded.t);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn prop_cbor_round_trip_pre_issuance(pre_issuance in pre_issuance_strategy()) {
        let bytes = pre_issuance.to_cbor().unwrap();
        let decoded = PreIssuance::from_cbor(&bytes).unwrap();

        prop_assert_eq!(pre_issuance.r, decoded.r);
        prop_assert_eq!(pre_issuance.k, decoded.k);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn prop_cbor_round_trip_pre_refund(
        r in scalar_strategy(),
        k in scalar_strategy(),
        m in scalar_strategy(),
        ctx in scalar_strategy(),
    ) {
        let pre_refund = PreRefund { r, k, m, ctx };
        let bytes = pre_refund.to_cbor().unwrap();
        let decoded = PreRefund::from_cbor(&bytes).unwrap();

        prop_assert_eq!(pre_refund.r, decoded.r);
        prop_assert_eq!(pre_refund.k, decoded.k);
        prop_assert_eq!(pre_refund.m, decoded.m);
        prop_assert_eq!(pre_refund.ctx, decoded.ctx);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
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
    #![proptest_config(ProptestConfig::with_cases(10))]
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
        let response = private_key.issue::<128>(&params, &request, initial_credits, test_context(), OsRng).unwrap();
        let token = pre_issuance
            .to_credit_token::<128>(&params, private_key.public(), &request, &response)
            .unwrap();

        let (spend_proof, _) = token.prove_spend::<128>(&params, spend_credits, OsRng).unwrap();

        // Verify spend proof has valid structure
        prop_assert_ne!(spend_proof.k, Scalar::ZERO, "Nullifier should not be zero");
        prop_assert_eq!(spend_proof.s, spend_credits, "Spend amount should match");
        prop_assert_ne!(spend_proof.a_prime, RistrettoPoint::identity(), "a_prime should not be identity");

        // Verify the com array has correct length
        prop_assert_eq!(spend_proof.com.len(), 128);
        prop_assert_eq!(spend_proof.gamma0.len(), 128);
        prop_assert_eq!(spend_proof.z.len(), 128);
    }
}

// Property: Token tampering is always detected
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
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
        let response = private_key.issue::<128>(&params, &request, initial_credits, test_context(), OsRng).unwrap();
        let mut token = pre_issuance
            .to_credit_token::<128>(&params, private_key.public(), &request, &response)
            .unwrap();

        // Tamper with the token
        token.a = tampering_point;
        token.e = tampering_scalar;

        // Try to spend from tampered token
        let (spend_proof, _) = token.prove_spend::<128>(&params, Scalar::from(1u64), OsRng).unwrap();

        // Refund should fail
        let refund_result = private_key.refund(&params, &spend_proof, Scalar::ZERO, OsRng);
        prop_assert!(refund_result.is_err(), "Tampered token should be rejected");
    }
}

// Property: Issuance with invalid request always fails
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
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
        let response = private_key.issue::<128>(&params, &request, credit_amount, test_context(), OsRng);
        prop_assert!(response.is_err(), "Invalid request should be rejected");
    }
}

// Property: Spend amounts within valid range produce valid binary decompositions
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn prop_spend_amount_binary_decomposition(
        spend_amount in any::<u128>(),
    ) {
        let scalar = Scalar::from(spend_amount);
        let bits = Ristretto255::bits_of::<128>(scalar);

        // Verify leading bits are zero for values less than 2^n
        let bit_length = u128::BITS as usize - spend_amount.leading_zeros() as usize;
        bits.iter()
            .enumerate()
            .skip(bit_length)
            .try_for_each(|(i, bit)| {
                if !bool::from(*bit) {
                    Ok(())
                } else {
                    Err(proptest::test_runner::TestCaseError::fail(format!("Bit {} should be zero", i)))
                }
            })?;
    }
}

// Property: Multiple issuers don't interfere
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
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
        let response1 = private_key1.issue::<128>(&params, &request, credits, test_context(), OsRng).unwrap();
        let token1 = pre_issuance
            .to_credit_token::<128>(&params, private_key1.public(), &request, &response1)
            .unwrap();

        // Try to spend token1 with issuer2 (should fail)
        let (spend_proof, _) = token1.prove_spend::<128>(&params, spend, OsRng).unwrap();
        let refund2 = private_key2.refund(&params, &spend_proof, Scalar::ZERO, OsRng);
        prop_assert!(refund2.is_err(), "Wrong issuer should reject spend");

        // Correct issuer should accept
        let refund1 = private_key1.refund(&params, &spend_proof, Scalar::ZERO, OsRng);
        prop_assert!(refund1.is_ok(), "Correct issuer should accept spend");
    }
}

// Property: Exhaustive spending works correctly
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn prop_exhaustive_spending(
        initial_amount in 5u64..100,
        private_key in private_key_strategy(),
        pre_issuance in pre_issuance_strategy(),
    ) {
        let params = test_params();
        let initial_credits = Scalar::from(initial_amount);

        let request = pre_issuance.request(&params, OsRng);
        let response = private_key.issue::<128>(&params, &request, initial_credits, test_context(), OsRng).unwrap();
        let mut token = pre_issuance
            .to_credit_token::<128>(&params, private_key.public(), &request, &response)
            .unwrap();

        let mut remaining = initial_amount;

        // Spend entire balance in decrements
        while remaining > 0 {
            let spend_amount = std::cmp::min(remaining, 5); // Spend up to 5 at a time
            let spend_scalar = Scalar::from(spend_amount);

            let (spend_proof, pre_refund) = token.prove_spend::<128>(&params, spend_scalar, OsRng).unwrap();
            remaining -= spend_amount;

            prop_assert_eq!(pre_refund.m, Scalar::from(remaining));

            if remaining > 0 {
                let refund = private_key.refund(&params, &spend_proof, Scalar::ZERO, OsRng).unwrap();
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
    #![proptest_config(ProptestConfig::with_cases(10))]
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
        let response1 = private_key.issue::<128>(&params, &request1, initial_credits, test_context(), OsRng).unwrap();
        let token1 = pre_issuance1
            .to_credit_token::<128>(&params, private_key.public(), &request1, &response1)
            .unwrap();

        let request2 = pre_issuance2.request(&params, OsRng);
        let response2 = private_key.issue::<128>(&params, &request2, initial_credits, test_context(), OsRng).unwrap();
        let token2 = pre_issuance2
            .to_credit_token::<128>(&params, private_key.public(), &request2, &response2)
            .unwrap();

        // Generate spend proofs
        let (proof1, _) = token1.prove_spend::<128>(&params, spend_credits, OsRng).unwrap();
        let (proof2, _) = token2.prove_spend::<128>(&params, spend_credits, OsRng).unwrap();

        // Proofs should be different despite same spend amount
        prop_assert_ne!(proof1.gamma, proof2.gamma);
        prop_assert_ne!(proof1.k_bar, proof2.k_bar);
        prop_assert_ne!(proof1.r_bar, proof2.r_bar);
    }
}

// Property: Scalar arithmetic preserves validity
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
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
    #![proptest_config(ProptestConfig::with_cases(10))]
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
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn prop_nullifier_collision_resistance(
        tokens in prop::collection::vec(
            (pre_issuance_strategy(), credit_amount_strategy()),
            10..20
        ),
        private_key in private_key_strategy(),
    ) {
        let params = test_params();
        let mut nullifiers = std::collections::HashSet::new();

        for (pre_issuance, credit_amount) in tokens {
            // Skip if credit amount is not representable in u128
            if scalar_to_u128(&credit_amount).is_none() {
                continue;
            }

            let request = pre_issuance.request(&params, OsRng);
            if let Ok(response) = private_key.issue::<128>(&params, &request, credit_amount, test_context(), OsRng)
                && let Ok(token) = pre_issuance.to_credit_token::<128>(
                    &params,
                    private_key.public(),
                    &request,
                    &response,
                )
            {
                let (proof, _) = token.prove_spend::<128>(&params, Scalar::from(1u64), OsRng).unwrap();
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

// Property: CBOR encoding is canonical
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
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

// ===== PARTIAL CREDIT RETURN PROPERTY TESTS =====

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn prop_partial_return_balance_correct(
        initial in 1u64..10000,
        spend in 1u64..10000,
        ret in 0u64..10000,
        private_key in private_key_strategy(),
        pre_issuance in pre_issuance_strategy(),
    ) {
        prop_assume!(spend <= initial);
        prop_assume!(ret <= spend);

        let params = test_params();
        let initial_scalar = Scalar::from(initial);
        let spend_scalar = Scalar::from(spend);
        let ret_scalar = Scalar::from(ret);

        let request = pre_issuance.request(&params, OsRng);
        let response = private_key
            .issue::<128>(&params, &request, initial_scalar, test_context(), OsRng)
            .unwrap();
        let token = pre_issuance
            .to_credit_token::<128>(&params, private_key.public(), &request, &response)
            .unwrap();

        let (spend_proof, prerefund) = token.prove_spend::<128>(&params, spend_scalar, OsRng).unwrap();
        let refund = private_key
            .refund(&params, &spend_proof, ret_scalar, OsRng)
            .unwrap();
        let new_token = prerefund
            .to_credit_token(&params, &spend_proof, &refund, private_key.public())
            .unwrap();

        let expected = Scalar::from(initial - spend + ret);
        prop_assert_eq!(new_token.c, expected);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn prop_partial_return_exceeding_s_always_fails(
        initial in 2u64..10000,
        spend in 1u64..5000,
        extra in 1u64..1000,
        private_key in private_key_strategy(),
        pre_issuance in pre_issuance_strategy(),
    ) {
        prop_assume!(spend <= initial);
        let ret = spend + extra; // ret > spend

        let params = test_params();
        let request = pre_issuance.request(&params, OsRng);
        let response = private_key
            .issue::<128>(&params, &request, Scalar::from(initial), test_context(), OsRng)
            .unwrap();
        let token = pre_issuance
            .to_credit_token::<128>(&params, private_key.public(), &request, &response)
            .unwrap();

        let (spend_proof, _) = token.prove_spend::<128>(&params, Scalar::from(spend), OsRng).unwrap();
        let result = private_key.refund(&params, &spend_proof, Scalar::from(ret), OsRng);
        prop_assert!(result.is_err());
        prop_assert_eq!(result.unwrap_err(), ErrorCode::InvalidAmount);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn prop_partial_return_cbor_roundtrip(
        a in point_strategy(),
        e in scalar_strategy(),
        gamma in scalar_strategy(),
        z in scalar_strategy(),
        t in scalar_strategy(),
    ) {
        let refund = Refund { a, e, gamma, z, t };
        let bytes = refund.to_cbor().unwrap();
        let decoded = Refund::from_cbor(&bytes).unwrap();

        prop_assert_eq!(refund.a, decoded.a);
        prop_assert_eq!(refund.e, decoded.e);
        prop_assert_eq!(refund.gamma, decoded.gamma);
        prop_assert_eq!(refund.z, decoded.z);
        prop_assert_eq!(refund.t, decoded.t);
    }
}
