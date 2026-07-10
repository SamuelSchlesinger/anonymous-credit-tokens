# Anonymous Credit Tokens

![crates.io](https://img.shields.io/crates/v/anonymous-credit-tokens.svg)
[![Rust](https://github.com/SamuelSchlesinger/anonymous-credit-tokens/actions/workflows/rust.yml/badge.svg)](https://github.com/SamuelSchlesinger/anonymous-credit-tokens/actions/workflows/rust.yml)

A Rust implementation of an Anonymous Credit Scheme (ACS) that enables privacy-preserving payment systems for web applications and services.

## WARNING

This cryptography is experimental and unaudited. Do not use in production environments without thorough security review.

## Overview

This library implements the Anonymous Credit Scheme designed by Jonathan Katz and Samuel Schlesinger (see [design document](docs/design.pdf)). The system allows:

- **Credit Issuance**: Services can issue digital credit tokens to users
- **Anonymous Spending**: Users can spend these credits without revealing their identity
- **Double-Spend Prevention**: The system prevents credits from being used multiple times
- **Privacy-Preserving Refunds**: Unspent credits can be refunded without compromising user privacy

The implementation uses BBS signatures and zero-knowledge proofs to ensure both security and privacy, making it suitable for integration into web services and distributed systems.

### Key Concepts

1. **Issuer**: The service that creates and validates credit tokens (typically your backend server)
2. **Client**: The user who receives, holds, and spends credit tokens (typically your users)
3. **Credit Token**: A cryptographic token representing a certain amount of credits
4. **Nullifier**: A unique identifier used to prevent double-spending

### Integration Architecture

```
┌──────────┐     ┌──────────────┐     ┌─────────────┐
│  Client  │     │   Service    │     │  Database   │
│  App     │◄────┤   Backend    │◄────┤  (Nullifier │
│          │     │   (Issuer)   │     │   Storage)  │
└──────────┘     └──────────────┘     └─────────────┘
```

## Features

- **Anonymity**: Clients can spend credits without revealing their identity or linking their behavior over time
- **Double-spending prevention**: Each nullifier can only be used once, meaning every credit token can be spent once
- **Fiscally sound**: Clients cannot spend more credits than have been issued
- **Efficient**: Optimized cryptographic operations for web service integration

## Server Integration Guide

### Key Management

The issuer must securely generate and store a keypair:

```rust
use anonymous_credit_tokens::PrivateKey;
use rand_core::OsRng;

// Generate a keypair on service startup
let private_key = PrivateKey::random(OsRng);
let public_key = private_key.public();

// The public_key should be shared with clients
// The private_key should be securely stored
```

### Nullifier Database

Implement a database to track used nullifiers:

```rust
use curve25519_dalek::Scalar;

// Example interface for a nullifier database
trait NullifierStore {
    fn is_used(&self, nullifier: &Scalar) -> bool;
    fn mark_used(&mut self, nullifier: Scalar);
}

// Example implementation using a concurrent HashMap
struct InMemoryNullifierStore {
    used_nullifiers: Arc<RwLock<HashSet<Scalar>>>,
}
```

### API Endpoints

A typical service implementation would include these endpoints:

1. **Issue Credit**: Process client issuance requests and issue credit tokens
2. **Process Spend**: Verify spending proofs and issue refunds
3. **Get Public Key**: Provide the issuer's public key to clients

## Usage Examples

### Key Generation

```rust
use anonymous_credit_tokens::PrivateKey;
use rand_core::OsRng;

// Generate a keypair for your service
let private_key = PrivateKey::random(OsRng);
let public_key = private_key.public();
```

### Scalar Conversion Utilities

Credit amounts are plain `u128` values in the API, bounded by
`MAX_CREDITS = 3^80 - 1`. Protocol values that arrive as scalars can be
decoded with `scalar_to_u128`:

```rust
use anonymous_credit_tokens::scalar_to_u128;
use curve25519_dalek::Scalar;

let scalar = Scalar::from(500u64);
assert_eq!(scalar_to_u128(&scalar), Some(500));

// Conversion returns None if the scalar is outside the u128 range.
let large_scalar = Scalar::ZERO - Scalar::ONE;
assert_eq!(scalar_to_u128(&large_scalar), None);
```

### Issuing Credits

Tokens are bound to a request context scalar `ctx` that both parties
derive from shared application context:

```rust
use anonymous_credit_tokens::{Params, PreIssuance, PrivateKey};
use curve25519_dalek::Scalar;
use rand_core::OsRng;

// Client-side: Prepare for issuance
let preissuance = PreIssuance::random(OsRng);
let params = Params::new("example-org", "payment-api", "production", "2024-01-15");
let issuance_request = preissuance.request(&params, OsRng);

// Server-side: Process the request (credit amount: 20)
let ctx = Scalar::from(42u64); // derived from application context
let issuance_response = private_key
    .issue(&params, &issuance_request, 20, ctx, OsRng)
    .unwrap();

// Client-side: Construct the credit token
let credit_token = preissuance
    .to_credit_token(&params, private_key.public(), &issuance_request, &issuance_response, ctx)
    .unwrap();
```

### Spending Credits

A spend declares a public spend amount `s` and a public top-up amount
`a` (0 for a plain spend). The issuer may return part of the spent
amount with the partial refund parameter `t`, bounded by
`max(0, s - a)`:

```rust
// Client-side: Creates a spending proof (spending 10 out of 20 credits,
// with no top-up)
let (spend_proof, prerefund) = credit_token.prove_spend(&params, 10, 0, OsRng).unwrap();

// Server-side: Verify and process the spending proof
// IMPORTANT: Check that the nullifier hasn't been used before
let nullifier = spend_proof.nullifier();
if nullifier_store.is_used(&nullifier) {
    return Err("Double-spend attempt detected");
}
nullifier_store.mark_used(nullifier);

// Server-side: Create a refund, keeping the full spend amount (t = 0)
let refund = private_key.refund(&params, &spend_proof, 0, OsRng).unwrap();

// Client-side: Construct a new credit token with remaining credits
let new_credit_token = prerefund
    .to_credit_token(&params, &spend_proof, &refund, private_key.public())
    .unwrap();
```

### Top-Ups

Credits can be added to a token during a spend. The top-up amount is a
public value bound by the proof, so the issuer authorizes it simply by
verifying the proof with it (for example, after an out-of-band
purchase tied to the request context):

```rust
// Client spends 10 credits while adding 100 purchased credits:
// the new balance is c - 10 + 100.
let (spend_proof, prerefund) = credit_token.prove_spend(&params, 10, 100, OsRng).unwrap();

// The issuer sees s = 10 and a = 100 in the proof and only proceeds
// if its policy authorizes the top-up.
let refund = private_key.refund(&params, &spend_proof, 0, OsRng).unwrap();
```

### Complete Transaction Lifecycle

```rust
use anonymous_credit_tokens::{Params, PreIssuance, PrivateKey};
use curve25519_dalek::Scalar;
use rand_core::OsRng;

// 1. System Initialization
let params = Params::new("example-org", "payment-api", "production", "2024-01-15");
let private_key = PrivateKey::random(OsRng);
let ctx = Scalar::from(42u64);

// 2. User Registration/Credit Issuance
// Client prepares for issuance
let preissuance = PreIssuance::random(OsRng);
let issuance_request = preissuance.request(&params, OsRng);

// Server issues 40 credits
let issuance_response = private_key
    .issue(&params, &issuance_request, 40, ctx, OsRng)
    .unwrap();

// Client receives the credit token
let credit_token1 = preissuance
    .to_credit_token(&params, private_key.public(), &issuance_request, &issuance_response, ctx)
    .unwrap();

// 3. First Purchase/Transaction
// Client spends 20 credits
let (spend_proof, prerefund) = credit_token1.prove_spend(&params, 20, 0, OsRng).unwrap();

// Server checks nullifier and processes the spending
let nullifier = spend_proof.nullifier();
if nullifier_store.is_used(&nullifier) {
    return Err("Double-spend attempt detected");
}
nullifier_store.mark_used(nullifier);

// Server issues a refund, returning 5 of the 20 spent credits
let refund = private_key.refund(&params, &spend_proof, 5, OsRng).unwrap();

// Client receives a new credit token with 25 credits remaining
let credit_token2 = prerefund
    .to_credit_token(&params, &spend_proof, &refund, private_key.public())
    .unwrap();

// 4. Second Purchase/Transaction
// Client spends the remaining 25 credits
let (spend_proof2, prerefund2) = credit_token2.prove_spend(&params, 25, 0, OsRng).unwrap();

// Server processes as before...
```

## Cryptographic Details

This implementation uses:

- Ristretto points (via curve25519-dalek) for elliptic curve operations
- Privately verifiable BBS-style signatures for anonymous credentials
- Sigma protocol proofs (via the sigma-proofs crate, following
  draft-irtf-cfrg-sigma-protocols) to demonstrate valid spending
- Blake3 for deriving the system parameters
- Base-3 digit decomposition for range proofs, covering credit values
  in [0, 3^80)

### How It Works

1. **Key Generation**: The issuer creates a keypair
2. **Credit Issuance**:
   - Client generates a random identifier and a blinding factor
   - Client creates a commitment to these values and sends it to the issuer
   - Issuer creates a BBS+ signature on the commitment and credit amount
   - Client verifies the signature and constructs a credit token
3. **Spending Protocol**:
   - Client creates a zero-knowledge proof of valid token ownership
   - Client proves that the remaining balance is non-negative
   - Client includes a nullifier to prevent double-spending
   - Issuer verifies the proof and checks the nullifier database
   - Issuer creates a new signature for the refund token
   - Client constructs a new credit token with the remaining balance

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

## Implementation in Web Services

### Backend Integration

1. **Key Management**:
   - Generate and securely store the issuer's private key
   - Implement key rotation procedures
   - Consider using a Hardware Security Module (HSM) for production

2. **Database Requirements**:
   - Store used nullifiers in a high-performance database
   - Index nullifiers for fast lookups
   - Nullifiers must be stored permanently to prevent double-spending

3. **API Endpoints**:
   - POST `/api/credits/issue`: Process issuance requests
   - POST `/api/credits/spend`: Process spending proofs
   - GET `/api/credits/public-key`: Provide the issuer's public key

### Client Integration

1. **Client Libraries**:
   - Wrap the cryptographic operations in a client-side library
   - Securely store credit tokens in client-side storage
   - Implement error handling and retry logic

2. **User Experience**:
   - Abstract the cryptographic operations from the user
   - Show credit balances and spending options
   - Handle connectivity issues gracefully

## Security Considerations

To ensure the security of your implementation:

1. **Double-Spending Prevention**:
   - Maintain a reliable database of used nullifiers
   - Implement efficient lookup procedures
   - Consider distributed consistency requirements

2. **Key Security**:
   - Protect the issuer's private key using appropriate security measures
   - Implement key rotation procedures
   - Use secure random number generation for all operations

3. **Client-Side Security**:
   - Protect credit tokens from theft or manipulation
   - Use secure local storage options
   - Implement proper error handling

## License

See the [LICENSE](LICENSE) file for details.

## References

The implementation is based on the Anonymous Credit Scheme designed by Jonathan Katz and Samuel Schlesinger. For more details:

- [IETF Draft Specification](https://samuelschlesinger.github.io/ietf-anonymous-credit-tokens/draft-schlesinger-cfrg-act.html) - The formal specification being developed for standardization
- [Design Document](docs/design.pdf) - The original design document

## Disclaimer

This is not an officially supported Google product. This project is not
eligible for the [Google Open Source Software Vulnerability Rewards
Program](https://bughunters.google.com/open-source-security).
