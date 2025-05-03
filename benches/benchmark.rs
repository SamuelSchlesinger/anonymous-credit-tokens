use anonymous_credit_tokens::{Params, PreIssuance, PrivateKey};
use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};
use curve25519_dalek::Scalar;
use rand::{Rng, thread_rng};
use rand_core::OsRng;
use std::sync::Arc;

// Create a shared parameter object once for all benchmarks
fn create_params() -> Arc<Params> {
    Arc::new(Params::default())
}

fn key_generation_benchmark(c: &mut Criterion) {
    c.bench_function("key_generation", |b| {
        b.iter(|| {
            black_box(PrivateKey::random(OsRng));
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
    // Precompute params
    let params = create_params();

    c.bench_function("issuance_request", |b| {
        b.iter_batched(
            || {
                let preissuance = PreIssuance::random(OsRng);
                (preissuance, Arc::clone(&params))
            },
            |(preissuance, params)| black_box(preissuance.request(&params, OsRng)),
            BatchSize::SmallInput,
        )
    });
}

fn issuance_benchmark(c: &mut Criterion) {
    // Precompute params
    let params = create_params();

    c.bench_function("issuance", |b| {
        b.iter_batched(
            || {
                let private_key = PrivateKey::random(OsRng);
                let preissuance = PreIssuance::random(OsRng);
                let issuance_request = preissuance.request(&params, OsRng);
                let credit_amount = Scalar::from(thread_rng().gen_range(10..1000) as u64);
                (
                    private_key,
                    Arc::clone(&params),
                    issuance_request,
                    credit_amount,
                )
            },
            |(private_key, params, issuance_request, credit_amount)| {
                black_box(
                    private_key
                        .issue(&params, &issuance_request, black_box(credit_amount), OsRng)
                        .unwrap(),
                )
            },
            BatchSize::SmallInput,
        )
    });
}

fn token_creation_benchmark(c: &mut Criterion) {
    // Precompute params
    let params = create_params();

    c.bench_function("token_creation", |b| {
        b.iter_batched(
            || {
                let private_key = PrivateKey::random(OsRng);
                let preissuance = PreIssuance::random(OsRng);
                let issuance_request = preissuance.request(&params, OsRng);
                let credit_amount = Scalar::from(thread_rng().gen_range(10..1000) as u64);
                let issuance_response = private_key
                    .issue(&params, &issuance_request, credit_amount, OsRng)
                    .unwrap();
                (
                    preissuance,
                    Arc::clone(&params),
                    private_key,
                    issuance_request,
                    issuance_response,
                )
            },
            |(preissuance, params, private_key, issuance_request, issuance_response)| {
                black_box(
                    preissuance
                        .to_credit_token(
                            &params,
                            private_key.public(),
                            &issuance_request,
                            &issuance_response,
                        )
                        .unwrap(),
                )
            },
            BatchSize::SmallInput,
        )
    });
}

fn spending_proof_benchmark(c: &mut Criterion) {
    // Precompute params
    let params = create_params();

    c.bench_function("spending_proof", |b| {
        b.iter_batched(
            || {
                let private_key = PrivateKey::random(OsRng);
                let preissuance = PreIssuance::random(OsRng);
                let issuance_request = preissuance.request(&params, OsRng);

                // Random credit amount between 20 and 1000
                let credit_amount = Scalar::from(thread_rng().gen_range(20..1000) as u64);

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

                // Random charge amount between 1 and credit_amount-1
                let credit_value =
                    u64::from_le_bytes(credit_amount.as_bytes()[0..8].try_into().unwrap());
                let max_charge = if credit_value > 1 {
                    credit_value - 1
                } else {
                    1
                };
                let charge = Scalar::from(thread_rng().gen_range(1..=max_charge) as u64);

                (credit_token, Arc::clone(&params), charge)
            },
            |(credit_token, params, charge)| {
                black_box(credit_token.prove_spend(&params, black_box(charge), OsRng))
            },
            BatchSize::SmallInput,
        )
    });
}

fn refund_benchmark(c: &mut Criterion) {
    // Precompute params
    let params = create_params();

    c.bench_function("refund", |b| {
        b.iter_batched(
            || {
                let private_key = PrivateKey::random(OsRng);
                let preissuance = PreIssuance::random(OsRng);
                let issuance_request = preissuance.request(&params, OsRng);

                // Random credit amount between 20 and 1000
                let credit_amount = Scalar::from(thread_rng().gen_range(20..1000) as u64);

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

                // Random charge amount between 1 and credit_amount-1
                let credit_value =
                    u64::from_le_bytes(credit_amount.as_bytes()[0..8].try_into().unwrap());
                let max_charge = if credit_value > 1 {
                    credit_value - 1
                } else {
                    1
                };
                let charge = Scalar::from(thread_rng().gen_range(1..=max_charge) as u64);

                let (spend_proof, _) = credit_token.prove_spend(&params, charge, OsRng);
                (private_key, Arc::clone(&params), spend_proof)
            },
            |(private_key, params, spend_proof)| {
                black_box(private_key.refund(&params, &spend_proof, OsRng).unwrap())
            },
            BatchSize::SmallInput,
        )
    });
}

fn refund_token_creation_benchmark(c: &mut Criterion) {
    // Precompute params
    let params = create_params();

    c.bench_function("refund_token_creation", |b| {
        b.iter_batched(
            || {
                let private_key = PrivateKey::random(OsRng);
                let preissuance = PreIssuance::random(OsRng);
                let issuance_request = preissuance.request(&params, OsRng);

                // Random credit amount between 20 and 1000
                let credit_amount = Scalar::from(thread_rng().gen_range(20..1000) as u64);

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

                // Random charge amount between 1 and credit_amount-1
                let credit_value =
                    u64::from_le_bytes(credit_amount.as_bytes()[0..8].try_into().unwrap());
                let max_charge = if credit_value > 1 {
                    credit_value - 1
                } else {
                    1
                };
                let charge = Scalar::from(thread_rng().gen_range(1..=max_charge) as u64);

                let (spend_proof, prerefund) = credit_token.prove_spend(&params, charge, OsRng);
                let refund = private_key.refund(&params, &spend_proof, OsRng).unwrap();
                (
                    prerefund,
                    spend_proof,
                    refund,
                    private_key,
                    Arc::clone(&params),
                )
            },
            |(prerefund, spend_proof, refund, private_key, params)| {
                black_box(
                    prerefund
                        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
                        .unwrap(),
                )
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(
    benches,
    key_generation_benchmark,
    preissuance_generation_benchmark,
    issuance_request_benchmark,
    issuance_benchmark,
    token_creation_benchmark,
    spending_proof_benchmark,
    refund_benchmark,
    refund_token_creation_benchmark,
);
criterion_main!(benches);
