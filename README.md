# Anonymous Credits

An (incomplete) implementation of Anonymous Credits in Rust.

## Completed

Issuance

## TODO

Implement the spending protocol. The hardest part here is going to be the range proof,
we're going to use the bit-sum-decomposition approach rather than SHARP so its easier
to make it constant time.
