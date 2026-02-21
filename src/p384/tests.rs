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
use elliptic_curve::ops::Reduce;
use p384_crate::ProjectivePoint;
use proptest::prelude::*;
use rand_core::OsRng;

impl TestCiphersuite for P384 {
    fn test_context() -> Scalar {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"test-request-context:example.com/api/charge");
        let mut output = [0u8; 48];
        let mut reader = hasher.finalize_xof();
        reader.fill(&mut output);
        <Scalar as Reduce<p384_crate::U384>>::reduce(p384_crate::U384::from_be_slice(&output))
    }
}

// Instantiate all common tests for P384
crate::instantiate_tests!(P384);

// ── Local wrappers for proptest helpers ─────────────────────────────────

fn scalar_from_u128(v: u128) -> Scalar {
    P384::scalar_from_u128(v)
}

fn bits_of<const L: usize>(s: Scalar) -> [subtle::Choice; L] {
    P384::bits_of::<L>(s)
}

fn test_context() -> Scalar {
    <P384 as TestCiphersuite>::test_context()
}

// ── Ciphersuite-specific tests ──────────────────────────────────────────

#[test]
fn test_params_generation_deterministic() {
    let params1 = Params::new("test-org", "test-service", "test", "2024-01-01").unwrap();
    let params2 = Params::new("test-org", "test-service", "test", "2024-01-01").unwrap();

    assert_eq!(params1.h1, params2.h1);
    assert_eq!(params1.h2, params2.h2);
    assert_eq!(params1.h3, params2.h3);
    assert_eq!(params1.h4, params2.h4);

    let params3 = Params::new("different-org", "test-service", "test", "2024-01-01").unwrap();
    assert_ne!(params1.h1, params3.h1);
}

// ===== PROPERTY-BASED TESTING WITH PROPTEST =====

fn scalar_strategy() -> impl Strategy<Value = Scalar> {
    // Generate 48 random bytes and reduce into the P-384 scalar field
    (prop::array::uniform32(any::<u8>()), prop::array::uniform16(any::<u8>()))
        .prop_map(|(a, b)| {
            let mut wide = [0u8; 48];
            wide[..32].copy_from_slice(&a);
            wide[32..].copy_from_slice(&b);
            <Scalar as Reduce<p384_crate::U384>>::reduce(p384_crate::U384::from_be_slice(&wide))
        })
}

fn credit_amount_strategy() -> impl Strategy<Value = Scalar> {
    any::<u128>().prop_map(scalar_from_u128)
}

fn point_strategy() -> impl Strategy<Value = ProjectivePoint> {
    scalar_strategy().prop_map(|s| ProjectivePoint::GENERATOR * s)
}

fn private_key_strategy() -> impl Strategy<Value = PrivateKey> {
    scalar_strategy().prop_map(|x| {
        let w = ProjectivePoint::GENERATOR * x;
        PrivateKey {
            x,
            public: PublicKey { w },
        }
    })
}

fn pre_issuance_strategy() -> impl Strategy<Value = PreIssuance> {
    (scalar_strategy(), scalar_strategy()).prop_map(|(r, k)| PreIssuance { r, k })
}

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

fn test_params() -> Params {
    Params::new("test-org", "test-service", "test-env", "2024-01-01").unwrap()
}

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
            prop_assert_eq!(token.c, credit_amount);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn prop_binary_decomposition_correctness(value in any::<u128>()) {
        let scalar = scalar_from_u128(value);
        let bits = bits_of::<128>(scalar);

        let reconstructed = bits.iter()
            .enumerate()
            .fold(Scalar::ZERO, |acc, (i, bit)| {
                if bool::from(*bit) {
                    acc + scalar_from_u128(2u128.pow(i as u32))
                } else {
                    acc
                }
            });

        prop_assert_eq!(scalar, reconstructed);
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
    fn prop_spend_refund_balance_preservation(
        initial_amount in 1u64..10000,
        spend_amount in 1u64..10000,
        private_key in private_key_strategy(),
        pre_issuance in pre_issuance_strategy(),
    ) {
        let params = test_params();
        let initial_credits = Scalar::from(initial_amount as u128);
        let spend_credits = Scalar::from(spend_amount as u128);

        prop_assume!(spend_amount <= initial_amount);

        let request = pre_issuance.request(&params, OsRng);
        let response = private_key.issue::<128>(&params, &request, initial_credits, test_context(), OsRng).unwrap();
        let token = pre_issuance
            .to_credit_token::<128>(&params, private_key.public(), &request, &response)
            .unwrap();

        let (spend_proof, pre_refund) = token.prove_spend::<128>(&params, spend_credits, OsRng).unwrap();

        let expected_remaining = initial_credits - spend_credits;
        prop_assert_eq!(pre_refund.m, expected_remaining);

        if let Ok(refund) = private_key.refund(&params, &spend_proof, Scalar::ZERO, OsRng) {
            let new_token = pre_refund
                .to_credit_token(&params, &spend_proof, &refund, private_key.public())
                .unwrap();

            prop_assert_eq!(new_token.c, expected_remaining);
        }
    }
}
