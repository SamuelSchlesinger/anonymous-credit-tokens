use anoncreds_rs::{Params, PreIssuance, PrivateKey};
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use curve25519_dalek::Scalar;
use rand_core::OsRng;

fn key_generation_benchmark(c: &mut Criterion) {
    c.bench_function("key_generation", |b| {
        b.iter(|| {
            black_box(PrivateKey::random(OsRng));
        })
    });
}

fn params_generation_benchmark(c: &mut Criterion) {
    c.bench_function("params_default", |b| {
        b.iter(|| {
            black_box(Params::default());
        })
    });
}

fn preissuance_generation_benchmark(c: &mut Criterion) {
    c.bench_function("preissuance_random", |b| {
        b.iter(|| {
            black_box(PreIssuance::random(OsRng));
        })
    });
}

fn issuance_request_benchmark(c: &mut Criterion) {
    let preissuance = PreIssuance::random(OsRng);

    c.bench_function("issuance_request", |b| {
        b.iter(|| {
            black_box(preissuance.request(OsRng));
        })
    });
}

fn issuance_benchmark(c: &mut Criterion) {
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let issuance_request = preissuance.request(OsRng);
    let credit_amount = Scalar::from(20u64);

    c.bench_function("issuance", |b| {
        b.iter(|| {
            black_box(
                private_key
                    .issue(&issuance_request, black_box(credit_amount), OsRng)
                    .unwrap(),
            );
        })
    });
}

fn token_creation_benchmark(c: &mut Criterion) {
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let issuance_request = preissuance.request(OsRng);
    let issuance_response = private_key
        .issue(&issuance_request, Scalar::from(20u64), OsRng)
        .unwrap();

    c.bench_function("token_creation", |b| {
        b.iter(|| {
            black_box(
                preissuance
                    .to_credit_token(private_key.public(), &issuance_request, &issuance_response)
                    .unwrap(),
            );
        })
    });
}

fn spending_proof_benchmark(c: &mut Criterion) {
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let issuance_request = preissuance.request(OsRng);
    let issuance_response = private_key
        .issue(&issuance_request, Scalar::from(20u64), OsRng)
        .unwrap();
    let credit_token = preissuance
        .to_credit_token(private_key.public(), &issuance_request, &issuance_response)
        .unwrap();
    let charge = Scalar::from(10u64);

    c.bench_function("spending_proof", |b| {
        b.iter(|| {
            black_box(credit_token.prove_spend(black_box(charge), private_key.public(), OsRng));
        })
    });
}

// The following benchmarks are commented out because the functionality is not implemented yet

/*
fn refund_benchmark(c: &mut Criterion) {
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let issuance_request = preissuance.request(OsRng);
    let issuance_response = private_key
        .issue(&issuance_request, Scalar::from(20u64), OsRng)
        .unwrap();
    let credit_token = preissuance
        .to_credit_token(private_key.public(), &issuance_request, &issuance_response)
        .unwrap();
    let charge = Scalar::from(10u64);
    let (spend_proof, _) = credit_token.prove_spend(charge, private_key.public(), OsRng);

    c.bench_function("refund", |b| {
        b.iter(|| {
            black_box(private_key.refund(&spend_proof, OsRng).unwrap());
        })
    });
}

fn refund_token_creation_benchmark(c: &mut Criterion) {
    let private_key = PrivateKey::random(OsRng);
    let preissuance = PreIssuance::random(OsRng);
    let issuance_request = preissuance.request(OsRng);
    let issuance_response = private_key
        .issue(&issuance_request, Scalar::from(20u64), OsRng)
        .unwrap();
    let credit_token = preissuance
        .to_credit_token(private_key.public(), &issuance_request, &issuance_response)
        .unwrap();
    let charge = Scalar::from(10u64);
    let (spend_proof, prerefund) = credit_token.prove_spend(charge, private_key.public(), OsRng);
    let refund = private_key.refund(&spend_proof, OsRng).unwrap();

    c.bench_function("refund_token_creation", |b| {
        b.iter(|| {
            black_box(prerefund.to_credit_token(&spend_proof, &refund, private_key.public()).unwrap());
        })
    });
}
*/

// Benchmark full issuance flow (key generation to token creation)
fn full_issuance_flow_benchmark(c: &mut Criterion) {
    c.bench_function("full_issuance_flow", |b| {
        b.iter(|| {
            let private_key = PrivateKey::random(OsRng);
            let preissuance = PreIssuance::random(OsRng);
            let issuance_request = preissuance.request(OsRng);
            let issuance_response = private_key
                .issue(&issuance_request, Scalar::from(20u64), OsRng)
                .unwrap();
            black_box(
                preissuance
                    .to_credit_token(private_key.public(), &issuance_request, &issuance_response)
                    .unwrap(),
            );
        })
    });
}

// Benchmark full spending flow (token creation to spending proof)
fn full_spending_flow_benchmark(c: &mut Criterion) {
    c.bench_function("full_spending_flow", |b| {
        b.iter(|| {
            let private_key = PrivateKey::random(OsRng);
            let preissuance = PreIssuance::random(OsRng);
            let issuance_request = preissuance.request(OsRng);
            let issuance_response = private_key
                .issue(&issuance_request, Scalar::from(20u64), OsRng)
                .unwrap();
            let credit_token = preissuance
                .to_credit_token(private_key.public(), &issuance_request, &issuance_response)
                .unwrap();
            let charge = Scalar::from(10u64);
            black_box(credit_token.prove_spend(charge, private_key.public(), OsRng));
        })
    });
}

criterion_group!(
    benches,
    key_generation_benchmark,
    params_generation_benchmark,
    preissuance_generation_benchmark,
    issuance_request_benchmark,
    issuance_benchmark,
    token_creation_benchmark,
    spending_proof_benchmark,
    full_issuance_flow_benchmark,
    full_spending_flow_benchmark,
);
criterion_main!(benches);
