use anonymous_credit_tokens_public::{Params, PreIssuance, PrivateKey, scalar_zero};
use bls12_381::Scalar;
use criterion::{
    AxisScale, BatchSize, BenchmarkId, Criterion, PlotConfiguration, black_box, criterion_group,
    criterion_main,
};
use rand::{Rng, thread_rng};
use rand_core::OsRng;
use std::sync::Arc;

fn create_params() -> Arc<Params> {
    Arc::new(Params::new(
        "bench-org",
        "bench-service",
        "bench-env",
        "2024-01-01",
    ))
}

/// Max credit value that fits in L bits: min(2^L - 1, 999).
fn max_credit(l: u32) -> u64 {
    if l >= 64 {
        999
    } else {
        std::cmp::min((1u64 << l) - 1, 999)
    }
}

// ---------------------------------------------------------------------------
// L-independent benchmarks
// ---------------------------------------------------------------------------

fn key_generation_benchmark(c: &mut Criterion) {
    c.bench_function("key_generation", |b| {
        b.iter(|| black_box(PrivateKey::random(OsRng)))
    });
}

fn preissuance_generation_benchmark(c: &mut Criterion) {
    c.bench_function("preissuance_random", |b| {
        b.iter(|| black_box(PreIssuance::random(OsRng)))
    });
}

fn issuance_request_benchmark(c: &mut Criterion) {
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

fn token_creation_benchmark(c: &mut Criterion) {
    let params = create_params();
    c.bench_function("token_creation", |b| {
        b.iter_batched(
            || {
                let private_key = PrivateKey::random(OsRng);
                let preissuance = PreIssuance::random(OsRng);
                let issuance_request = preissuance.request(&params, OsRng);
                let credit_amount = Scalar::from(thread_rng().gen_range(10u64..1000));
                let issuance_response = private_key
                    .issue::<16>(
                        &params,
                        &issuance_request,
                        credit_amount,
                        scalar_zero(),
                        OsRng,
                    )
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
                        .to_credit_token::<16>(
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

// ---------------------------------------------------------------------------
// L-dependent benchmarks
// ---------------------------------------------------------------------------

macro_rules! bench_issuance {
    ($group:expr, $params:expr, $l:literal) => {
        $group.bench_with_input(BenchmarkId::from_parameter($l), &$l, |b, _| {
            b.iter_batched(
                || {
                    let private_key = PrivateKey::random(OsRng);
                    let preissuance = PreIssuance::random(OsRng);
                    let issuance_request = preissuance.request(&$params, OsRng);
                    let credit = Scalar::from(thread_rng().gen_range(1..=max_credit($l)));
                    (private_key, issuance_request, credit)
                },
                |(pk, req, credit)| {
                    black_box(
                        pk.issue::<$l>(&$params, &req, credit, scalar_zero(), OsRng)
                            .unwrap(),
                    )
                },
                BatchSize::SmallInput,
            )
        });
    };
}

fn issuance_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("issuance");
    group.plot_config(PlotConfiguration::default().summary_scale(AxisScale::Logarithmic));
    let params = create_params();

    bench_issuance!(group, params, 1);
    bench_issuance!(group, params, 2);
    bench_issuance!(group, params, 4);
    bench_issuance!(group, params, 8);
    bench_issuance!(group, params, 16);
    bench_issuance!(group, params, 32);
    bench_issuance!(group, params, 64);
    bench_issuance!(group, params, 128);

    group.finish();
}

macro_rules! bench_spending_proof {
    ($group:expr, $params:expr, $l:literal) => {
        $group.bench_with_input(BenchmarkId::from_parameter($l), &$l, |b, _| {
            b.iter_batched(
                || {
                    let private_key = PrivateKey::random(OsRng);
                    let preissuance = PreIssuance::random(OsRng);
                    let issuance_request = preissuance.request(&$params, OsRng);
                    let credit_val = thread_rng().gen_range(1..=max_credit($l));
                    let credit_amount = Scalar::from(credit_val);
                    let issuance_response = private_key
                        .issue::<$l>(
                            &$params,
                            &issuance_request,
                            credit_amount,
                            scalar_zero(),
                            OsRng,
                        )
                        .unwrap();
                    let credit_token = preissuance
                        .to_credit_token::<$l>(
                            &$params,
                            private_key.public(),
                            &issuance_request,
                            &issuance_response,
                        )
                        .unwrap();
                    let charge = Scalar::from(thread_rng().gen_range(1..=credit_val));
                    (credit_token, charge)
                },
                |(credit_token, charge)| {
                    black_box(credit_token.prove_spend::<$l>(&$params, charge, OsRng).unwrap())
                },
                BatchSize::SmallInput,
            )
        });
    };
}

fn spending_proof_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("spending_proof");
    group.plot_config(PlotConfiguration::default().summary_scale(AxisScale::Logarithmic));
    let params = create_params();

    bench_spending_proof!(group, params, 1);
    bench_spending_proof!(group, params, 2);
    bench_spending_proof!(group, params, 4);
    bench_spending_proof!(group, params, 8);
    bench_spending_proof!(group, params, 16);
    bench_spending_proof!(group, params, 32);
    bench_spending_proof!(group, params, 64);
    bench_spending_proof!(group, params, 128);

    group.finish();
}

macro_rules! bench_refund {
    ($group:expr, $params:expr, $l:literal) => {
        $group.bench_with_input(BenchmarkId::from_parameter($l), &$l, |b, _| {
            b.iter_batched(
                || {
                    let private_key = PrivateKey::random(OsRng);
                    let preissuance = PreIssuance::random(OsRng);
                    let issuance_request = preissuance.request(&$params, OsRng);
                    let credit_val = thread_rng().gen_range(1..=max_credit($l));
                    let credit_amount = Scalar::from(credit_val);
                    let issuance_response = private_key
                        .issue::<$l>(
                            &$params,
                            &issuance_request,
                            credit_amount,
                            scalar_zero(),
                            OsRng,
                        )
                        .unwrap();
                    let credit_token = preissuance
                        .to_credit_token::<$l>(
                            &$params,
                            private_key.public(),
                            &issuance_request,
                            &issuance_response,
                        )
                        .unwrap();
                    let charge = Scalar::from(thread_rng().gen_range(1..=credit_val));
                    let (spend_proof, _) = credit_token.prove_spend::<$l>(&$params, charge, OsRng).unwrap();
                    (private_key, spend_proof)
                },
                |(pk, spend_proof)| black_box(pk.refund(&$params, &spend_proof, scalar_zero(), OsRng).unwrap()),
                BatchSize::SmallInput,
            )
        });
    };
}

fn refund_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("refund");
    group.plot_config(PlotConfiguration::default().summary_scale(AxisScale::Logarithmic));
    let params = create_params();

    bench_refund!(group, params, 1);
    bench_refund!(group, params, 2);
    bench_refund!(group, params, 4);
    bench_refund!(group, params, 8);
    bench_refund!(group, params, 16);
    bench_refund!(group, params, 32);
    bench_refund!(group, params, 64);
    bench_refund!(group, params, 128);

    group.finish();
}

macro_rules! bench_refund_token_creation {
    ($group:expr, $params:expr, $l:literal) => {
        $group.bench_with_input(BenchmarkId::from_parameter($l), &$l, |b, _| {
            b.iter_batched(
                || {
                    let private_key = PrivateKey::random(OsRng);
                    let preissuance = PreIssuance::random(OsRng);
                    let issuance_request = preissuance.request(&$params, OsRng);
                    let credit_val = thread_rng().gen_range(1..=max_credit($l));
                    let credit_amount = Scalar::from(credit_val);
                    let issuance_response = private_key
                        .issue::<$l>(
                            &$params,
                            &issuance_request,
                            credit_amount,
                            scalar_zero(),
                            OsRng,
                        )
                        .unwrap();
                    let credit_token = preissuance
                        .to_credit_token::<$l>(
                            &$params,
                            private_key.public(),
                            &issuance_request,
                            &issuance_response,
                        )
                        .unwrap();
                    let charge = Scalar::from(thread_rng().gen_range(1..=credit_val));
                    let (spend_proof, prerefund) =
                        credit_token.prove_spend::<$l>(&$params, charge, OsRng).unwrap();
                    let refund = private_key.refund(&$params, &spend_proof, scalar_zero(), OsRng).unwrap();
                    (prerefund, spend_proof, refund, private_key)
                },
                |(prerefund, spend_proof, refund, private_key)| {
                    black_box(
                        prerefund
                            .to_credit_token(&$params, &spend_proof, &refund, private_key.public())
                            .unwrap(),
                    )
                },
                BatchSize::SmallInput,
            )
        });
    };
}

fn refund_token_creation_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("refund_token_creation");
    group.plot_config(PlotConfiguration::default().summary_scale(AxisScale::Logarithmic));
    let params = create_params();

    bench_refund_token_creation!(group, params, 1);
    bench_refund_token_creation!(group, params, 2);
    bench_refund_token_creation!(group, params, 4);
    bench_refund_token_creation!(group, params, 8);
    bench_refund_token_creation!(group, params, 16);
    bench_refund_token_creation!(group, params, 32);
    bench_refund_token_creation!(group, params, 64);
    bench_refund_token_creation!(group, params, 128);

    group.finish();
}

macro_rules! bench_public_verification {
    ($group:expr, $params:expr, $l:literal) => {
        $group.bench_with_input(BenchmarkId::from_parameter($l), &$l, |b, _| {
            b.iter_batched(
                || {
                    let private_key = PrivateKey::random(OsRng);
                    let preissuance = PreIssuance::random(OsRng);
                    let issuance_request = preissuance.request(&$params, OsRng);
                    let credit_val = thread_rng().gen_range(1..=max_credit($l));
                    let credit_amount = Scalar::from(credit_val);
                    let issuance_response = private_key
                        .issue::<$l>(
                            &$params,
                            &issuance_request,
                            credit_amount,
                            scalar_zero(),
                            OsRng,
                        )
                        .unwrap();
                    let credit_token = preissuance
                        .to_credit_token::<$l>(
                            &$params,
                            private_key.public(),
                            &issuance_request,
                            &issuance_response,
                        )
                        .unwrap();
                    let charge = Scalar::from(thread_rng().gen_range(1..=credit_val));
                    let (spend_proof, _) = credit_token.prove_spend::<$l>(&$params, charge, OsRng).unwrap();
                    let public_key = private_key.public().clone();
                    (public_key, spend_proof)
                },
                |(public_key, spend_proof)| {
                    black_box(
                        anonymous_credit_tokens_public::verify_spend_proof(&$params, &public_key, &spend_proof).unwrap()
                    )
                },
                BatchSize::SmallInput,
            )
        });
    };
}

fn public_verification_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("public_verification");
    group.plot_config(PlotConfiguration::default().summary_scale(AxisScale::Logarithmic));
    let params = create_params();

    bench_public_verification!(group, params, 1);
    bench_public_verification!(group, params, 2);
    bench_public_verification!(group, params, 4);
    bench_public_verification!(group, params, 8);
    bench_public_verification!(group, params, 16);
    bench_public_verification!(group, params, 32);
    bench_public_verification!(group, params, 64);
    bench_public_verification!(group, params, 128);

    group.finish();
}

criterion_group!(
    benches,
    // L-independent
    key_generation_benchmark,
    preissuance_generation_benchmark,
    issuance_request_benchmark,
    token_creation_benchmark,
    // L-dependent scaling
    issuance_scaling,
    spending_proof_scaling,
    refund_scaling,
    refund_token_creation_scaling,
    public_verification_scaling,
);
criterion_main!(benches);
