use crate::*;
use ff::Field;
use rand_core::OsRng;
use std::collections::HashSet;

fn test_context() -> Scalar {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"test-request-context:example.com/api/charge");
    let mut wide = [0u8; 64];
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut wide);
    Scalar::from_bytes_wide(&wide)
}

#[derive(Default)]
struct NullifierDb {
    used_nullifiers: HashSet<[u8; 32]>,
}

impl NullifierDb {
    fn new() -> Self {
        Self {
            used_nullifiers: HashSet::new(),
        }
    }

    fn is_spent(&self, nullifier: &Scalar) -> bool {
        self.used_nullifiers.contains(&nullifier.to_bytes())
    }

    fn record_spent(&mut self, nullifier: &Scalar) {
        self.used_nullifiers.insert(nullifier.to_bytes());
    }
}

#[test]
fn issuance() {
    use rand::{Rng, thread_rng};

    for _i in 0..10 {
        let private_key = PrivateKey::random(OsRng);
        let preissuance = PreIssuance::random(OsRng);
        let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
        let issuance_request = preissuance.request(&params, OsRng);

        let credit_amount = Scalar::from(thread_rng().gen_range(1..1000) as u64);

        let issuance_response = private_key
            .issue::<128>(
                &params,
                &issuance_request,
                credit_amount,
                test_context(),
                OsRng,
            )
            .unwrap();
        let _credit_token1 = preissuance
            .to_credit_token::<128>(
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
    for _i in 0..3 {
        let private_key = PrivateKey::random(OsRng);
        let preissuance = PreIssuance::random(OsRng);
        let issuance_request = preissuance.request(&params, OsRng);

        let total_credits = thread_rng().gen_range(100..2000) as u64;
        let credit_amount = Scalar::from(total_credits);

        let issuance_response = private_key
            .issue::<128>(
                &params,
                &issuance_request,
                credit_amount,
                test_context(),
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

        let first_charge = thread_rng().gen_range(1..=(total_credits / 2)) as u64;
        let charge1 = Scalar::from(first_charge);

        let (spend_proof, prerefund) =
            credit_token1.prove_spend::<128>(&params, charge1, OsRng).unwrap();
        let refund = private_key
            .refund(&params, &spend_proof, scalar_zero(), OsRng)
            .unwrap();
        let credit_token2 = prerefund
            .to_credit_token(&params, &spend_proof, &refund, private_key.public())
            .unwrap();

        let remaining_credits = total_credits - first_charge;
        let charge2 = Scalar::from(remaining_credits);

        let (spend_proof, prerefund) =
            credit_token2.prove_spend::<128>(&params, charge2, OsRng).unwrap();
        let refund = private_key
            .refund(&params, &spend_proof, scalar_zero(), OsRng)
            .unwrap();
        let _credit_token3 = prerefund
            .to_credit_token(&params, &spend_proof, &refund, private_key.public())
            .unwrap();
    }
}

#[test]
fn double_spend_prevention() {
    use rand::{Rng, thread_rng};

    let mut nullifier_db = NullifierDb::new();
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let issuance_request = preissuance.request(&params, OsRng);

    let total_credits = thread_rng().gen_range(100..1000) as u64;
    let credit_amount = Scalar::from(total_credits);

    let issuance_response = private_key
        .issue::<128>(
            &params,
            &issuance_request,
            credit_amount,
            test_context(),
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

    let first_charge = thread_rng().gen_range(1..=(total_credits / 3)) as u64;
    let charge1 = Scalar::from(first_charge);

    let (spend_proof1, prerefund1) =
        credit_token.prove_spend::<128>(&params, charge1, OsRng).unwrap();

    let nullifier = spend_proof1.nullifier();
    assert!(!nullifier_db.is_spent(&nullifier));

    let refund1 = private_key
        .refund(&params, &spend_proof1, scalar_zero(), OsRng)
        .unwrap();
    nullifier_db.record_spent(&nullifier);

    let new_token = prerefund1
        .to_credit_token(&params, &spend_proof1, &refund1, private_key.public())
        .unwrap();

    // Attempt double spend
    let second_charge = thread_rng().gen_range(1..=(total_credits / 2)) as u64;
    let charge2 = Scalar::from(second_charge);
    let (spend_proof2, _) =
        credit_token.prove_spend::<128>(&params, charge2, OsRng).unwrap();
    let nullifier2 = spend_proof2.nullifier();
    assert!(nullifier_db.is_spent(&nullifier2));

    // Spend from new token works
    let remaining = total_credits - first_charge;
    let third_charge = thread_rng().gen_range(1..remaining) as u64;
    let charge3 = Scalar::from(third_charge);
    let (spend_proof3, _) =
        new_token.prove_spend::<128>(&params, charge3, OsRng).unwrap();
    let nullifier3 = spend_proof3.nullifier();
    assert!(!nullifier_db.is_spent(&nullifier3));
}

#[test]
fn spend_exact_balance() {
    use rand::{Rng, thread_rng};

    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let issuance_request = preissuance.request(&params, OsRng);

    let total_credits = thread_rng().gen_range(10..1000) as u64;
    let credit_amount = Scalar::from(total_credits);

    let issuance_response = private_key
        .issue::<128>(
            &params,
            &issuance_request,
            credit_amount,
            test_context(),
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

    let (spend_proof, prerefund) =
        credit_token.prove_spend::<128>(&params, credit_amount, OsRng).unwrap();
    assert_eq!(prerefund.m, Scalar::zero());

    let refund = private_key
        .refund(&params, &spend_proof, scalar_zero(), OsRng)
        .unwrap();
    let new_token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();
    assert_eq!(new_token.c, Scalar::zero());
}

#[test]
fn sequential_spends() {
    let mut nullifier_db = NullifierDb::new();
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let issuance_request = preissuance.request(&params, OsRng);

    let initial_credits = 200u64;
    let initial_amount = Scalar::from(initial_credits);

    let issuance_response = private_key
        .issue::<128>(
            &params,
            &issuance_request,
            initial_amount,
            test_context(),
            OsRng,
        )
        .unwrap();
    let mut current_token = preissuance
        .to_credit_token::<128>(
            &params,
            private_key.public(),
            &issuance_request,
            &issuance_response,
        )
        .unwrap();

    let per_spend_amount = 20u64;
    let spend_amount = Scalar::from(per_spend_amount);
    let mut remaining = initial_credits;

    for i in 1..=5 {
        let (spend_proof, prerefund) =
            current_token.prove_spend::<128>(&params, spend_amount, OsRng).unwrap();
        remaining -= per_spend_amount;

        assert_eq!(
            prerefund.m,
            Scalar::from(remaining),
            "Remaining balance incorrect after spend {}",
            i
        );

        let nullifier = spend_proof.nullifier();
        assert!(!nullifier_db.is_spent(&nullifier));
        nullifier_db.record_spent(&nullifier);

        let refund = private_key
            .refund(&params, &spend_proof, scalar_zero(), OsRng)
            .unwrap();
        current_token = prerefund
            .to_credit_token(&params, &spend_proof, &refund, private_key.public())
            .unwrap();

        assert_eq!(current_token.c, Scalar::from(remaining));
    }

    let expected_final = initial_credits - (5 * per_spend_amount);
    assert_eq!(current_token.c, Scalar::from(expected_final));
}

#[test]
fn attempt_overspend() {
    use rand::{Rng, thread_rng};

    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let issuance_request = preissuance.request(&params, OsRng);

    let credit_value = thread_rng().gen_range(20..500) as u64;
    let credit_amount = Scalar::from(credit_value);

    let issuance_response = private_key
        .issue::<128>(
            &params,
            &issuance_request,
            credit_amount,
            test_context(),
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

    let overspend_value = credit_value + thread_rng().gen_range(1..100) as u64;
    let overspend_amount = Scalar::from(overspend_value);
    let result = credit_token.prove_spend::<128>(&params, overspend_amount, OsRng);
    assert!(result.is_err());
}

#[test]
fn zero_spend_scenario() {
    use rand::{Rng, thread_rng};

    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let issuance_request = preissuance.request(&params, OsRng);

    let credit_value = thread_rng().gen_range(10..1000) as u64;
    let credit_amount = Scalar::from(credit_value);

    let issuance_response = private_key
        .issue::<128>(
            &params,
            &issuance_request,
            credit_amount,
            test_context(),
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

    let zero_spend = Scalar::from(0u64);
    let (spend_proof, prerefund) =
        credit_token.prove_spend::<128>(&params, zero_spend, OsRng).unwrap();
    let refund = private_key
        .refund(&params, &spend_proof, scalar_zero(), OsRng)
        .unwrap();
    assert_eq!(prerefund.m, credit_amount);

    let new_token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();
    assert_eq!(new_token.c, credit_amount);
}

#[test]
fn invalid_issuance_request() {
    let private_key = PrivateKey::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let preissuance = PreIssuance::random(OsRng);
    let valid_request = preissuance.request(&params, OsRng);

    let tampered_request = IssuanceRequest {
        big_k: valid_request.big_k,
        gamma: valid_request.gamma,
        k_bar: valid_request.k_bar + Scalar::one(),
        r_bar: valid_request.r_bar,
    };

    let issuance_response = private_key.issue::<128>(
        &params,
        &tampered_request,
        Scalar::from(20u64),
        test_context(),
        OsRng,
    );
    assert!(issuance_response.is_err());

    let issuance_response = private_key.issue::<128>(
        &params,
        &valid_request,
        Scalar::from(20u64),
        test_context(),
        OsRng,
    );
    assert!(issuance_response.is_ok());
}

#[test]
fn invalid_proof_verification() {
    use rand::{Rng, thread_rng};

    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let request = preissuance.request(&params, OsRng);

    let credit_value = thread_rng().gen_range(50..500) as u64;
    let credit_amount = Scalar::from(credit_value);

    let response = private_key
        .issue::<128>(&params, &request, credit_amount, test_context(), OsRng)
        .unwrap();
    let token = preissuance
        .to_credit_token::<128>(&params, private_key.public(), &request, &response)
        .unwrap();

    let spend_value = thread_rng().gen_range(10..credit_value / 2) as u64;
    let spend_amount = Scalar::from(spend_value);
    let (spend_proof, _) = token.prove_spend::<128>(&params, spend_amount, OsRng).unwrap();

    let tampered_value = spend_value + thread_rng().gen_range(1..10) as u64;
    let tampered_proof = SpendProof {
        s: Scalar::from(tampered_value),
        ..spend_proof
    };

    let refund_result = private_key.refund(&params, &tampered_proof, scalar_zero(), OsRng);
    assert!(refund_result.is_err());
}

#[test]
fn tampered_issuance_response() {
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let request = preissuance.request(&params, OsRng);
    let response = private_key
        .issue::<128>(
            &params,
            &request,
            Scalar::from(50u64),
            test_context(),
            OsRng,
        )
        .unwrap();

    // Tamper with e
    let tampered_response = IssuanceResponse {
        a: response.a,
        e: response.e + Scalar::one(),
        c: response.c,
        ctx: response.ctx,
    };

    let token_result = preissuance
        .to_credit_token::<128>(&params, private_key.public(), &request, &tampered_response);
    assert!(token_result.is_err());

    // Original should work
    let token_result =
        preissuance.to_credit_token::<128>(&params, private_key.public(), &request, &response);
    assert!(token_result.is_ok());
}

#[test]
fn tampered_refund_verification() {
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let request = preissuance.request(&params, OsRng);
    let response = private_key
        .issue::<128>(
            &params,
            &request,
            Scalar::from(50u64),
            test_context(),
            OsRng,
        )
        .unwrap();
    let token = preissuance
        .to_credit_token::<128>(&params, private_key.public(), &request, &response)
        .unwrap();

    let spend_amount = Scalar::from(20u64);
    let (spend_proof, prerefund) =
        token.prove_spend::<128>(&params, spend_amount, OsRng).unwrap();
    let refund = private_key
        .refund(&params, &spend_proof, scalar_zero(), OsRng)
        .unwrap();

    // Tamper with refund e value
    let tampered_refund = Refund {
        a: refund.a,
        e: refund.e + Scalar::one(),
        t: refund.t,
    };

    let new_token_result = prerefund.to_credit_token(
        &params,
        &spend_proof,
        &tampered_refund,
        private_key.public(),
    );
    assert!(new_token_result.is_err());

    // Original should work
    let new_token_result =
        prerefund.to_credit_token(&params, &spend_proof, &refund, private_key.public());
    assert!(new_token_result.is_ok());
}

#[test]
fn issuance_rejects_zero_credits() {
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let request = preissuance.request(&params, OsRng);
    let response = private_key.issue::<128>(&params, &request, Scalar::zero(), test_context(), OsRng);
    assert_eq!(response.unwrap_err(), ErrorCode::InvalidAmount);
}

#[test]
fn spend_with_identity_a_prime() {
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let request = preissuance.request(&params, OsRng);
    let response = private_key
        .issue::<128>(
            &params,
            &request,
            Scalar::from(20u64),
            test_context(),
            OsRng,
        )
        .unwrap();
    let token = preissuance
        .to_credit_token::<128>(&params, private_key.public(), &request, &response)
        .unwrap();

    let (mut spend_proof, _) = token
        .prove_spend::<128>(&params, Scalar::from(10u64), OsRng)
        .unwrap();
    spend_proof.a_prime = G1Projective::identity();

    let refund_result = private_key.refund(&params, &spend_proof, scalar_zero(), OsRng);
    assert!(refund_result.is_err());
}

#[test]
fn public_verification_of_spend_proof() {
    // Core new capability: verify spend proof with ONLY the public key
    let private_key = PrivateKey::random(OsRng);
    let public_key = private_key.public().clone();
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let request = preissuance.request(&params, OsRng);
    let response = private_key
        .issue::<128>(
            &params,
            &request,
            Scalar::from(100u64),
            test_context(),
            OsRng,
        )
        .unwrap();
    let token = preissuance
        .to_credit_token::<128>(&params, &public_key, &request, &response)
        .unwrap();

    let (spend_proof, _prerefund) = token
        .prove_spend::<128>(&params, Scalar::from(30u64), OsRng)
        .unwrap();

    // Anyone with the public key can verify
    let result = verify_spend_proof(&params, &public_key, &spend_proof);
    assert!(result.is_ok(), "Public verification should succeed");

    // Tampered proof should fail
    let mut tampered = spend_proof.clone();
    tampered.s = Scalar::from(31u64);
    let result = verify_spend_proof(&params, &public_key, &tampered);
    assert!(result.is_err(), "Tampered proof should fail public verification");
}

#[test]
fn test_params_generation_deterministic() {
    let params1 = Params::new("test-org", "test-service", "test", "2024-01-01");
    let params2 = Params::new("test-org", "test-service", "test", "2024-01-01");

    assert_eq!(
        G1Affine::from(params1.h1).to_compressed(),
        G1Affine::from(params2.h1).to_compressed()
    );
    assert_eq!(
        G1Affine::from(params1.h2).to_compressed(),
        G1Affine::from(params2.h2).to_compressed()
    );

    let params3 = Params::new("different-org", "test-service", "test", "2024-01-01");
    assert_ne!(
        G1Affine::from(params1.h1).to_compressed(),
        G1Affine::from(params3.h1).to_compressed()
    );
}

#[test]
fn transcript_add_elements_test() {
    let point1 = G1Projective::generator();
    let point2 = G1Projective::generator() * Scalar::from(2u64);
    let point3 = G1Projective::generator() * Scalar::from(3u64);

    let params = Params::random(OsRng);

    let mut transcript1 = crate::transcript::Transcript::new(&params, b"test");
    transcript1.add_elements([&point1, &point2, &point3].into_iter());
    let challenge1 = transcript1.challenge();

    let mut transcript2 = crate::transcript::Transcript::new(&params, b"test");
    transcript2.add_element(&point1);
    transcript2.add_element(&point2);
    transcript2.add_element(&point3);
    let challenge2 = transcript2.challenge();

    assert_eq!(challenge1, challenge2);
}

#[test]
fn bits_of_test() {
    let x = scalar_from_u128(u128::MAX);
    let bits = crate::bits_of::<128>(x);
    bits.iter().for_each(|bit| assert!(bool::from(*bit)));

    let x = Scalar::from(0u64);
    let bits = crate::bits_of::<128>(x);
    bits.iter().for_each(|bit| assert!(!bool::from(*bit)));

    let x = Scalar::from(0b001u64);
    let bits = crate::bits_of::<128>(x);
    bits.iter().enumerate().for_each(|(i, bit)| {
        let expected = i == 0;
        assert_eq!(bool::from(*bit), expected);
    });

    let x = Scalar::from(7u64);
    let bits = crate::bits_of::<128>(x);
    bits.iter().enumerate().for_each(|(i, bit)| {
        let expected = i <= 2;
        assert_eq!(bool::from(*bit), expected);
    });
}

#[test]
fn scalar_roundtrip_u128() {
    // Test that scalar_from_u128 and scalar_to_u128 are inverse
    for v in [0u128, 1, 42, 1000, u64::MAX as u128, u128::MAX] {
        let s = scalar_from_u128(v);
        let back = scalar_to_u128(&s).unwrap();
        assert_eq!(v, back, "roundtrip failed for {}", v);
    }
}

#[test]
fn partial_return_basic() {
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let request = preissuance.request(&params, OsRng);

    let response = private_key
        .issue::<128>(
            &params,
            &request,
            Scalar::from(100u64),
            test_context(),
            OsRng,
        )
        .unwrap();
    let token = preissuance
        .to_credit_token::<128>(&params, private_key.public(), &request, &response)
        .unwrap();

    // Spend 30, issuer returns 10
    let (spend_proof, prerefund) = token
        .prove_spend::<128>(&params, Scalar::from(30u64), OsRng)
        .unwrap();

    let refund = private_key
        .refund(&params, &spend_proof, Scalar::from(10u64), OsRng)
        .unwrap();

    let new_token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();

    // 100 - 30 + 10 = 80
    assert_eq!(new_token.c, Scalar::from(80u64));
}

// CBOR roundtrip tests

#[test]
fn test_issuance_request_cbor_roundtrip() {
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let request = preissuance.request(&params, OsRng);

    let bytes = request.to_cbor().unwrap();
    let decoded = IssuanceRequest::from_cbor(&bytes).unwrap();

    assert_eq!(request.big_k, decoded.big_k);
    assert_eq!(request.gamma, decoded.gamma);
    assert_eq!(request.k_bar, decoded.k_bar);
    assert_eq!(request.r_bar, decoded.r_bar);
}

#[test]
fn test_issuance_response_cbor_roundtrip() {
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let request = preissuance.request(&params, OsRng);
    let response = private_key
        .issue::<128>(
            &params,
            &request,
            Scalar::from(50u64),
            test_context(),
            OsRng,
        )
        .unwrap();

    let bytes = response.to_cbor().unwrap();
    let decoded = IssuanceResponse::from_cbor(&bytes).unwrap();

    assert_eq!(response.a, decoded.a);
    assert_eq!(response.e, decoded.e);
    assert_eq!(response.c, decoded.c);
    assert_eq!(response.ctx, decoded.ctx);
}

#[test]
fn test_refund_cbor_roundtrip() {
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let request = preissuance.request(&params, OsRng);
    let response = private_key
        .issue::<128>(
            &params,
            &request,
            Scalar::from(50u64),
            test_context(),
            OsRng,
        )
        .unwrap();
    let token = preissuance
        .to_credit_token::<128>(&params, private_key.public(), &request, &response)
        .unwrap();
    let (spend_proof, _) = token
        .prove_spend::<128>(&params, Scalar::from(20u64), OsRng)
        .unwrap();
    let refund = private_key
        .refund(&params, &spend_proof, scalar_zero(), OsRng)
        .unwrap();

    let bytes = refund.to_cbor().unwrap();
    let decoded = Refund::from_cbor(&bytes).unwrap();

    assert_eq!(refund.a, decoded.a);
    assert_eq!(refund.e, decoded.e);
    assert_eq!(refund.t, decoded.t);
}

#[test]
fn test_private_key_cbor_roundtrip() {
    let private_key = PrivateKey::random(OsRng);
    let bytes = private_key.to_cbor().unwrap();
    let decoded = PrivateKey::from_cbor(&bytes).unwrap();

    assert_eq!(private_key.x, decoded.x);
    assert_eq!(private_key.public.w, decoded.public.w);
}

#[test]
fn test_public_key_cbor_roundtrip() {
    let private_key = PrivateKey::random(OsRng);
    let public_key = private_key.public();
    let bytes = public_key.to_cbor().unwrap();
    let decoded = PublicKey::from_cbor(&bytes).unwrap();

    assert_eq!(public_key.w, decoded.w);
}

#[test]
fn test_pre_issuance_cbor_roundtrip() {
    let pre_issuance = PreIssuance::random(OsRng);
    let bytes = pre_issuance.to_cbor().unwrap();
    let decoded = PreIssuance::from_cbor(&bytes).unwrap();

    assert_eq!(pre_issuance.r, decoded.r);
    assert_eq!(pre_issuance.k, decoded.k);
}

#[test]
fn test_credit_token_cbor_roundtrip() {
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let request = preissuance.request(&params, OsRng);
    let response = private_key
        .issue::<128>(
            &params,
            &request,
            Scalar::from(50u64),
            test_context(),
            OsRng,
        )
        .unwrap();
    let token = preissuance
        .to_credit_token::<128>(&params, private_key.public(), &request, &response)
        .unwrap();

    let bytes = token.to_cbor().unwrap();
    let decoded = CreditToken::from_cbor(&bytes).unwrap();

    assert_eq!(token.a, decoded.a);
    assert_eq!(token.e, decoded.e);
    assert_eq!(token.k, decoded.k);
    assert_eq!(token.r, decoded.r);
    assert_eq!(token.c, decoded.c);
    assert_eq!(token.ctx, decoded.ctx);
}

#[test]
fn test_pre_refund_cbor_roundtrip() {
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let params = Params::new("test-org", "test-service", "test-env", "2024-01-01");
    let request = preissuance.request(&params, OsRng);
    let response = private_key
        .issue::<128>(
            &params,
            &request,
            Scalar::from(50u64),
            test_context(),
            OsRng,
        )
        .unwrap();
    let token = preissuance
        .to_credit_token::<128>(&params, private_key.public(), &request, &response)
        .unwrap();
    let (spend_proof, prerefund) = token
        .prove_spend::<128>(&params, Scalar::from(20u64), OsRng)
        .unwrap();

    let bytes = prerefund.to_cbor().unwrap();
    let decoded = PreRefund::from_cbor(&bytes).unwrap();

    assert_eq!(prerefund.r, decoded.r);
    assert_eq!(prerefund.k, decoded.k);
    assert_eq!(prerefund.m, decoded.m);
    assert_eq!(prerefund.ctx, decoded.ctx);
}

#[test]
fn test_error_msg_cbor_roundtrip() {
    let error = ErrorMsg {
        error_code: ErrorCode::InvalidProof,
        error_message: "proof verification failed".to_string(),
    };
    let bytes = error.to_cbor().unwrap();
    let decoded = ErrorMsg::from_cbor(&bytes).unwrap();

    assert_eq!(error.error_code, decoded.error_code);
    assert_eq!(error.error_message, decoded.error_message);
}
