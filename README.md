# Anonymous Credits

A Rust implementation of an Anonymous Credit Scheme (ACS) that enables
privacy-preserving payment systems.

## Overview

This library implements the Anonymous Credit Scheme designed by Jonathan Katz
and Samuel Schlesinger (see [design document](docs/design.pdf)). The system
allows:

- An issuer to issue credit tokens to clients
- Clients to spend these credits anonymously
- Prevention of double-spending through nullifiers
- Privacy-preserving refunds for unspent credits

The implementation uses BBS signatures and zero-knowledge proofs to ensure both
security and privacy.

## Features

- **Anonymity**: Clients can spend credits without revealing their identity
- **Unlinkability**: Spending activities cannot be linked to each other
- **Double-spending prevention**: Each nullifier can only be used once
- **Fiscally sound**: Clients cannot spend more credits than they have

## Usage Examples

### Key Generation

The issuer must generate a keypair:

```rust
use anoncreds_rs::PrivateKey;
use rand_core::OsRng;

// Issuer generates a keypair
let private_key = PrivateKey::random(OsRng);
let public_key = private_key.public();
```

### Issuing Credits

To issue credits to a client:

```rust
use anoncreds_rs::{PreIssuance, PrivateKey};
use curve25519_dalek::Scalar;
use rand_core::OsRng;

// Client prepares for issuance
let preissuance = PreIssuance::random(OsRng);
let issuance_request = preissuance.request(OsRng);

// Issuer processes the request (credit amount: 20)
let credit_amount = Scalar::from(20u64);
let issuance_response = private_key
    .issue(&issuance_request, credit_amount, OsRng)
    .unwrap();

// Client constructs the credit token
let credit_token = preissuance
    .to_credit_token(private_key.public(), &issuance_request, &issuance_response)
    .unwrap();
```

### Spending Credits

A client can spend some credits and receive a refund token for the remainder:

```rust
// Client creates a spending proof (spending 10 out of 20 credits)
let charge = Scalar::from(10u64);
let (spend_proof, prerefund) = credit_token.prove_spend(charge, OsRng);

// Issuer verifies and processes the spending proof
// The issuer should check that the nullifier hasn't been used before
let nullifier = spend_proof.nullifier();
// ... (check nullifier database)

// Issuer creates a refund
let refund = private_key.refund(&spend_proof, OsRng).unwrap();

// Client constructs a new credit token with remaining credits
let new_credit_token = prerefund
    .to_credit_token(&spend_proof, &refund, private_key.public())
    .unwrap();
```

### Complete Transaction Cycle

```rust
use anoncreds_rs::{PrivateKey, PreIssuance};
use curve25519_dalek::Scalar;
use rand_core::OsRng;

// Issuer generates a keypair
let private_key = PrivateKey::random(OsRng);

// Client prepares for issuance
let preissuance = PreIssuance::random(OsRng);
let issuance_request = preissuance.request(OsRng);

// Issuer issues 40 credits
let issuance_response = private_key
    .issue(&issuance_request, Scalar::from(40u64), OsRng)
    .unwrap();

// Client receives the credit token
let credit_token1 = preissuance
    .to_credit_token(private_key.public(), &issuance_request, &issuance_response)
    .unwrap();

// Client spends 20 credits
let charge = Scalar::from(20u64);
let (spend_proof, prerefund) = credit_token1.prove_spend(charge, OsRng);

// Issuer processes the spending and issues a refund
let refund = private_key.refund(&spend_proof, OsRng).unwrap();

// Client receives a new credit token with 20 credits remaining
let credit_token2 = prerefund
    .to_credit_token(&spend_proof, &refund, private_key.public())
    .unwrap();

// Client can spend the remaining credits
let charge = Scalar::from(20u64);
let (spend_proof2, prerefund2) = credit_token2.prove_spend(charge, OsRng);
let refund2 = private_key.refund(&spend_proof2, OsRng).unwrap();
let credit_token3 = prerefund2
    .to_credit_token(&spend_proof2, &refund2, private_key.public())
    .unwrap();
```

## Cryptographic Details

This implementation uses:

- Ristretto points (via curve25519-dalek) for elliptic curve operations
- BBS+ signatures for anonymous credentials
- Zero-knowledge proofs to demonstrate valid spending
- Blake3 for hashing in the transcript protocol
- Binary decomposition for range proofs

The scheme consists of three main components:
1. **Key Generation**: The issuer creates a keypair
2. **Token Issuance**: Clients obtain credit tokens through an interactive protocol
3. **Spending Protocol**: Clients can spend credits while preserving anonymity and receiving refunds for unspent credits

## Benchmarks

The project uses [Criterion.rs](https://github.com/bheisler/criterion.rs) for benchmarking the following operations:

- Key generation
- Pre-issuance
- Issuance request
- Issuance
- Token creation
- Spending proof generation
- Refund processing
- Refund token creation

To run the benchmarks:

```bash
cargo bench
```

Benchmark results will be available in the `target/criterion` directory as HTML reports.

## Security Considerations

To prevent double-spending, issuers must:
1. Maintain a database of used nullifiers
2. Check each spend request against this database before processing
3. Use high-quality randomness for key generation

To ensure their credit tokens are secure (and not already spent), clients must
use high-quality randomness for all operations.

## License

See the [LICENSE](LICENSE) file for details.

## References

The implementation is based on the Anonymous Credit Scheme designed by Jonathan
Katz and Samuel Schlesinger. For more details, see the [design
document](docs/design.pdf).
