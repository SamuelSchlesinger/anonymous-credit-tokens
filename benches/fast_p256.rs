use anonymous_credit_tokens::p256::{Params, PreIssuance, PrivateKey};
use criterion::{
    AxisScale, BatchSize, BenchmarkId, Criterion, PlotConfiguration, black_box, criterion_group,
    criterion_main,
};
use anonymous_credit_tokens::p256::Scalar;
use rand::{Rng, thread_rng};
use rand_core::OsRng;
use std::time::Duration;

/// Max credit value that fits in L bits: 2^L - 1.
fn max_credit(l: u32) -> u128 {
    if l >= 128 {
        u128::MAX
    } else {
        (1u128 << l) - 1
    }
}

macro_rules! bench_spend_and_refund {
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
                        .issue::<$l>(&$params, &issuance_request, credit_amount, Scalar::ZERO, OsRng)
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
                    (private_key, credit_token, charge)
                },
                |(private_key, credit_token, charge)| {
                    let (spend_proof, _prerefund) = black_box(
                        credit_token.prove_spend::<$l>(&$params, charge, OsRng).unwrap(),
                    );
                    black_box(
                        private_key.refund(&$params, &spend_proof, Scalar::ZERO, OsRng).unwrap(),
                    );
                },
                BatchSize::SmallInput,
            )
        });
    };
}

fn spend_and_refund(c: &mut Criterion) {
    let params = Params::new("bench-org", "bench-service", "bench-env", "2024-01-01");

    let mut group = c.benchmark_group("spend_and_refund");
    group.plot_config(PlotConfiguration::default().summary_scale(AxisScale::Logarithmic));
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(5));

    bench_spend_and_refund!(group, params, 8);
    bench_spend_and_refund!(group, params, 16);
    bench_spend_and_refund!(group, params, 32);
    bench_spend_and_refund!(group, params, 64);
    bench_spend_and_refund!(group, params, 128);

    group.finish();
}

criterion_group!(benches, spend_and_refund);
criterion_main!(benches);
