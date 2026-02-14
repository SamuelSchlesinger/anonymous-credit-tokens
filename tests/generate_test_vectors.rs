// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Deterministic test vector generation for the CFRG spec (Appendix A).
//!
//! Running this test regenerates the test vectors and splices them into
//! the spec markdown automatically:
//!
//!   cargo test --test generate_test_vectors
//!
//! Use `-- --nocapture` to also see the output on stdout.

use anonymous_credit_tokens::*;
use curve25519_dalek::Scalar;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::fmt::Write as FmtWrite;

/// Raw hex string from a byte slice.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hex of a scalar's little-endian bytes.
fn scalar_hex(s: &Scalar) -> String {
    hex(s.as_bytes())
}

/// Format a long hex string with 2-space indented continuation lines,
/// breaking every `width` hex characters.
fn fmt_hex_block(label: &str, bytes: &[u8], width: usize) -> String {
    let h = hex(bytes);
    let mut out = String::new();
    let chunks: Vec<&str> = h
        .as_bytes()
        .chunks(width)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    if chunks.len() <= 1 {
        writeln!(out, "{label}: {h}").unwrap();
    } else {
        writeln!(out, "{label}:").unwrap();
        for chunk in &chunks {
            writeln!(out, "  {chunk}").unwrap();
        }
    }
    out
}

/// Format a short scalar hex value on one line.
fn fmt_scalar_line(label: &str, s: &Scalar) -> String {
    format!("{label}:\n  {}\n", scalar_hex(s))
}

#[test]
fn generate_test_vectors() {
    // ── deterministic seed ──────────────────────────────────────
    let seed: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let domain_separator = "ACT-v1:test:vectors:v0:2025-01-01";
    let params = Params::new("test", "vectors", "v0", "2025-01-01");

    let c: u128 = 100;
    let s: u128 = 30;
    let ctx = Scalar::ZERO;

    // ── protocol run ────────────────────────────────────────────
    let private_key = PrivateKey::random(&mut rng);
    let sk_cbor = private_key.to_cbor().unwrap();
    let pk_cbor = private_key.public().to_cbor().unwrap();

    let preissuance = PreIssuance::random(&mut rng);
    let preissuance_cbor = preissuance.to_cbor().unwrap();

    let request = preissuance.request(&params, &mut rng);
    let request_cbor = request.to_cbor().unwrap();

    let response = private_key
        .issue::<8>(&params, &request, Scalar::from(c), ctx, &mut rng)
        .unwrap();
    let response_cbor = response.to_cbor().unwrap();

    let token = preissuance
        .to_credit_token::<8>(&params, private_key.public(), &request, &response)
        .unwrap();
    let token_cbor = token.to_cbor().unwrap();

    let (spend_proof, prerefund) = token.prove_spend::<8>(&params, Scalar::from(s), &mut rng).unwrap();
    let spend_proof_cbor = spend_proof.to_cbor().unwrap();
    let prerefund_cbor = prerefund.to_cbor().unwrap();

    let t: u128 = 10;
    let refund = private_key.refund::<8>(&params, &spend_proof, Scalar::from(t), &mut rng).unwrap();
    let refund_cbor = refund.to_cbor().unwrap();

    let new_token = prerefund
        .to_credit_token(&params, &spend_proof, &refund, private_key.public())
        .unwrap();
    let new_token_cbor = new_token.to_cbor().unwrap();

    let remaining = scalar_to_credit::<8>(&new_token.credits()).unwrap();
    assert_eq!(remaining, c - s + t, "remaining balance should be c - s + t");

    // ── build markdown ──────────────────────────────────────────
    let w = 64; // hex chars per line
    let mut md = String::new();

    // preamble
    writeln!(
        md,
        "The following test vector was generated deterministically using a"
    )
    .unwrap();
    writeln!(
        md,
        "ChaCha20 RNG seeded with the bytes `00 01 02 ... 1e 1f` and L=8."
    )
    .unwrap();
    writeln!(
        md,
        "The domain separator is `\"{domain_separator}\"`, credit amount"
    )
    .unwrap();
    writeln!(
        md,
        "c={c}, spend amount s={s}, partial return t={t}, and ctx=0. Values labelled `*_cbor`"
    )
    .unwrap();
    writeln!(
        md,
        "are the CBOR wire-format encodings (Section 4) of each protocol"
    )
    .unwrap();
    writeln!(md, "message, displayed in hexadecimal.").unwrap();
    writeln!(md).unwrap();
    writeln!(
        md,
        "Implementations SHOULD verify they can deserialize these CBOR"
    )
    .unwrap();
    writeln!(
        md,
        "messages and that a full protocol run with the same deterministic"
    )
    .unwrap();
    writeln!(md, "RNG produces identical output.").unwrap();
    writeln!(md).unwrap();

    // Parameters
    writeln!(md, "## Parameters").unwrap();
    writeln!(md).unwrap();
    writeln!(md, "~~~").unwrap();
    writeln!(md, "domain_separator: \"{domain_separator}\"").unwrap();
    writeln!(md, "L: 8").unwrap();
    writeln!(md, "c: {c}").unwrap();
    writeln!(md, "s: {s}").unwrap();
    writeln!(md, "t: {t}").unwrap();
    writeln!(md, "ctx: {}", scalar_hex(&ctx)).unwrap();
    writeln!(md, "~~~").unwrap();
    writeln!(md).unwrap();

    // Key Generation
    writeln!(md, "## Key Generation").unwrap();
    writeln!(md).unwrap();
    writeln!(md, "~~~").unwrap();
    write!(md, "{}", fmt_hex_block("sk_cbor", &sk_cbor, w)).unwrap();
    writeln!(md).unwrap();
    write!(md, "{}", fmt_hex_block("pk_cbor", &pk_cbor, w)).unwrap();
    writeln!(md, "~~~").unwrap();
    writeln!(md).unwrap();

    // Issuance
    writeln!(md, "## Issuance").unwrap();
    writeln!(md).unwrap();
    writeln!(md, "~~~").unwrap();
    write!(
        md,
        "{}",
        fmt_hex_block("preissuance_cbor", &preissuance_cbor, w)
    )
    .unwrap();
    writeln!(md).unwrap();
    write!(
        md,
        "{}",
        fmt_hex_block("issuance_request_cbor", &request_cbor, w)
    )
    .unwrap();
    writeln!(md).unwrap();
    write!(
        md,
        "{}",
        fmt_hex_block("issuance_response_cbor", &response_cbor, w)
    )
    .unwrap();
    writeln!(md).unwrap();
    write!(md, "{}", fmt_hex_block("credit_token_cbor", &token_cbor, w)).unwrap();
    writeln!(md, "~~~").unwrap();
    writeln!(md).unwrap();

    // Spending
    writeln!(md, "## Spending").unwrap();
    writeln!(md).unwrap();
    writeln!(md, "~~~").unwrap();
    write!(
        md,
        "{}",
        fmt_scalar_line("nullifier", &spend_proof.nullifier())
    )
    .unwrap();
    writeln!(md).unwrap();
    write!(md, "{}", fmt_scalar_line("context", &spend_proof.context())).unwrap();
    writeln!(md).unwrap();
    write!(md, "{}", fmt_scalar_line("charge", &spend_proof.charge())).unwrap();
    writeln!(md).unwrap();
    write!(
        md,
        "{}",
        fmt_hex_block("spend_proof_cbor", &spend_proof_cbor, w)
    )
    .unwrap();
    writeln!(md).unwrap();
    write!(
        md,
        "{}",
        fmt_hex_block("prerefund_cbor", &prerefund_cbor, w)
    )
    .unwrap();
    writeln!(md, "~~~").unwrap();
    writeln!(md).unwrap();

    // Refund
    writeln!(md, "## Refund").unwrap();
    writeln!(md).unwrap();
    writeln!(md, "~~~").unwrap();
    write!(md, "{}", fmt_hex_block("refund_cbor", &refund_cbor, w)).unwrap();
    writeln!(md, "~~~").unwrap();
    writeln!(md).unwrap();

    // Refund Token
    writeln!(md, "## Refund Token").unwrap();
    writeln!(md).unwrap();
    writeln!(md, "~~~").unwrap();
    write!(
        md,
        "{}",
        fmt_hex_block("refund_token_cbor", &new_token_cbor, w)
    )
    .unwrap();
    writeln!(md).unwrap();
    write!(
        md,
        "{}",
        fmt_scalar_line("refund_token_credits", &new_token.credits())
    )
    .unwrap();
    writeln!(md).unwrap();
    write!(
        md,
        "{}",
        fmt_scalar_line("refund_token_nullifier", &new_token.nullifier())
    )
    .unwrap();
    writeln!(md).unwrap();
    writeln!(md, "remaining_balance: {remaining}").unwrap();
    writeln!(md, "~~~").unwrap();

    // ── splice into spec ────────────────────────────────────────
    let spec_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/draft-act/draft-schlesinger-cfrg-act.md"
    );

    let spec = std::fs::read_to_string(spec_path).expect("could not read spec markdown");

    const START: &str = "<!-- TEST_VECTORS_START -->";
    const END: &str = "<!-- TEST_VECTORS_END -->";

    let start_idx = spec
        .find(START)
        .expect("missing TEST_VECTORS_START marker in spec");
    let end_idx = spec
        .find(END)
        .expect("missing TEST_VECTORS_END marker in spec");

    let mut new_spec = String::with_capacity(spec.len() + md.len());
    new_spec.push_str(&spec[..start_idx + START.len()]);
    new_spec.push('\n');
    new_spec.push_str(&md);
    new_spec.push_str(&spec[end_idx..]);

    std::fs::write(spec_path, &new_spec).expect("could not write spec markdown");

    // Also print to stdout for --nocapture inspection
    println!("{md}");
    println!("--- wrote test vectors to {spec_path}");
}
