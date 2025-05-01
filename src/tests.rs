use crate::*;
use rand_core::OsRng;

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