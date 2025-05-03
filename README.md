# Anonymous Credit Tokens

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

```rust
use anonymous_credit_tokens::{u32_to_scalar, scalar_to_u32};

// Convert u32 to Scalar for credit amounts
let credit_amount_u32 = 500u32;
let credit_amount_scalar = u32_to_scalar(credit_amount_u32);

// Use the scalar for issuing credits
// ...

// Convert back to u32 for display or other purposes
let amount_back = scalar_to_u32(&credit_amount_scalar).unwrap();
assert_eq!(amount_back, credit_amount_u32);

// Conversion will return None if the scalar is outside u32 range
let large_scalar = // ... some large scalar
let result = scalar_to_u32(&large_scalar); // Returns None if too large
```

### Issuing Credits

```rust
use anonymous_credit_tokens::{Params, PreIssuance, PrivateKey};
use curve25519_dalek::Scalar;
use rand_core::OsRng;

// Client-side: Prepare for issuance
let preissuance = PreIssuance::random(OsRng);
let params = Params::nothing_up_my_sleeve(b"innocence v1");
let issuance_request = preissuance.request(&params, OsRng);

// Server-side: Process the request (credit amount: 20)
let credit_amount = Scalar::from(20u64);
let issuance_response = private_key
    .issue(&params, &issuance_request, credit_amount, OsRng)
    .unwrap();

// Client-side: Construct the credit token
let credit_token = preissuance
    .to_credit_token(&params, private_key.public(), &issuance_request, &issuance_response)
    .unwrap();
```

### Spending Credits

```rust
// Client-side: Creates a spending proof (spending 10 out of 20 credits)
let charge = Scalar::from(10u64);
let (spend_proof, prerefund) = credit_token.prove_spend(&params, charge, OsRng);

// Server-side: Verify and process the spending proof
// IMPORTANT: Check that the nullifier hasn't been used before
let nullifier = spend_proof.nullifier();
if nullifier_store.is_used(&nullifier) {
    return Err("Double-spend attempt detected");
}
nullifier_store.mark_used(nullifier);

// Server-side: Create a refund
let refund = private_key.refund(&params, &spend_proof, OsRng).unwrap();

// Client-side: Construct a new credit token with remaining credits
let new_credit_token = prerefund
    .to_credit_token(&params, &spend_proof, &refund, private_key.public())
    .unwrap();
```

### Complete Transaction Lifecycle

```rust
use anonymous_credit_tokens::{PrivateKey, PreIssuance};
use curve25519_dalek::Scalar;
use rand_core::OsRng;

// 1. System Initialization
let params = Params::nothing_up_my_sleeve(b"innocence v1");
let private_key = PrivateKey::random(OsRng);

// 2. User Registration/Credit Issuance
// Client prepares for issuance
let preissuance = PreIssuance::random(OsRng);
let issuance_request = preissuance.request(&params, OsRng);

// Server issues 40 credits
let issuance_response = private_key
    .issue(&params, &issuance_request, Scalar::from(40u64), OsRng)
    .unwrap();

// Client receives the credit token
let credit_token1 = preissuance
    .to_credit_token(&params, private_key.public(), &issuance_request, &issuance_response)
    .unwrap();

// 3. First Purchase/Transaction
// Client spends 20 credits
let charge = Scalar::from(20u64);
let (spend_proof, prerefund) = credit_token1.prove_spend(&params, charge, OsRng);

// Server checks nullifier and processes the spending
let nullifier = spend_proof.nullifier();
if nullifier_store.is_used(&nullifier) {
    return Err("Double-spend attempt detected");
}
nullifier_store.mark_used(nullifier);

// Server issues a refund
let refund = private_key.refund(&params, &spend_proof, OsRng).unwrap();

// Client receives a new credit token with 20 credits remaining
let credit_token2 = prerefund
    .to_credit_token(&params, &spend_proof, &refund, private_key.public())
    .unwrap();

// 4. Second Purchase/Transaction
// Client spends remaining 20 credits
let charge = Scalar::from(20u64);
let (spend_proof2, prerefund2) = credit_token2.prove_spend(&params, charge, OsRng);

// Server processes as before...
```

## Cryptographic Details

This implementation uses:

- Ristretto points (via curve25519-dalek) for elliptic curve operations
- BBS+ signatures for anonymous credentials
- Zero-knowledge proofs to demonstrate valid spending
- Blake3 for hashing in the transcript protocol
- Binary decomposition for range proofs

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

The implementation is based on the Anonymous Credit Scheme designed by Jonathan Katz and Samuel Schlesinger. For more details, see the [design document](docs/design.pdf).
