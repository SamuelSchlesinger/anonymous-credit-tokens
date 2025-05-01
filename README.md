# Anonymous Credits

An (incomplete) implementation of Anonymous Credits in Rust.

## Completed

- Issuance
- Spending protocol

## TODO

- Implement the refund protocol

## Benchmarks

The project uses [Criterion.rs](https://github.com/bheisler/criterion.rs) for benchmarking. The following operations are benchmarked:

- Key generation
- Parameters generation
- Pre-issuance
- Issuance request
- Issuance
- Token creation
- Spending proof
- Full issuance flow
- Full spending flow

To run the benchmarks:

```bash
cargo bench
```

Benchmark results will be available in the `target/criterion` directory as HTML reports.
