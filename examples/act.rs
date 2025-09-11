/// Example showing issuance and spending of ACT credentials.
/// SPDX-License-Identifier: Apache-2.0
use std::collections::HashSet;

use anonymous_credit_tokens::{Params, PreIssuance, PrivateKey};
use curve25519_dalek::Scalar;
use rand_core::OsRng;

// Example interface for a nullifier database
trait NullifierStore {
    fn is_used(&self, nullifier: &Scalar) -> bool;
    fn mark_used(&mut self, nullifier: Scalar);
}

// Example implementation using a HashMap
#[derive(Default)]
struct InMemoryNullifierStore {
    used_nullifiers: HashSet<Scalar>,
}

impl NullifierStore for InMemoryNullifierStore {
    fn is_used(&self, nullifier: &Scalar) -> bool {
        self.used_nullifiers.contains(nullifier)
    }
    fn mark_used(&mut self, nullifier: Scalar) {
        if !self.used_nullifiers.insert(nullifier) {
            panic!("nullifier already exists")
        }
    }
}

fn main() {
    // 1. System Initialization
    let params = Params::new("example-org", "payment-api", "production", "2024-01-15");
    let private_key = PrivateKey::random(OsRng);
    let mut nullifier_store = InMemoryNullifierStore::default();

    // 2. User Registration/Credit Issuance
    // Client prepares for issuance
    let preissuance = PreIssuance::random(OsRng);
    let issuance_request = preissuance.request(&params, OsRng);

    // Server issues 40 credits
    let issuance_response = private_key
        .issue(&params, &issuance_request, Scalar::from(40u64), OsRng)
        .unwrap();

    // Client receives the credit token
    let mut credit_token = preissuance
        .to_credit_token(
            &params,
            private_key.public(),
            &issuance_request,
            &issuance_response,
        )
        .unwrap();
    println!("Credits: {:?}", credit_token.credits().to_bytes()[0]);

    // 3. First Purchase/Transaction
    // Client spends 20 credits
    let charge = Scalar::from(20u64);
    let (spend_proof, prerefund) = credit_token.prove_spend(&params, charge, OsRng);

    // Server checks nullifier and processes the spending
    let nullifier = spend_proof.nullifier();
    if nullifier_store.is_used(&nullifier) {
        panic!("Double-spend attempt detected");
    }
    nullifier_store.mark_used(nullifier);

    // Server issues a refund
    let refund = private_key.refund(&params, &spend_proof, OsRng).unwrap();

    // Client receives a new credit token with 20 credits remaining
    credit_token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();
    println!("Credits: {:?}", credit_token.credits().to_bytes()[0]);
}
