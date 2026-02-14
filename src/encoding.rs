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

//! TLS presentation language encoding for Anonymous Credit Token protocol messages.
//!
//! This module implements the wire format as specified in the IETF draft,
//! using TLS presentation language (RFC 8446 Section 3). Fixed-size fields
//! are encoded as raw bytes, and variable-length fields use a 2-byte
//! big-endian length prefix.

use crate::{
    CreditToken, IssuanceRequest, IssuanceResponse, PreIssuance, PreRefund, PrivateKey,
    PublicKey, Refund, SpendProof,
};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::{RistrettoPoint, Scalar};
use group::Group;

/// Error type for TLS presentation language encoding/decoding.
#[derive(Debug, PartialEq)]
pub enum EncodingError {
    /// Input data is too short to decode the expected structure.
    TooShort,
    /// A variable-length field exceeds the maximum representable length (u16::MAX).
    TooLong,
    /// A compressed Ristretto point could not be decompressed or is the identity.
    InvalidPoint,
    /// A scalar is not in canonical form (value >= group order).
    InvalidScalar,
    /// Trailing bytes remain after decoding.
    TrailingData,
}

// --- Low-level helpers ---

fn write_point(buf: &mut Vec<u8>, point: &RistrettoPoint) {
    buf.extend_from_slice(point.compress().as_bytes());
}

fn write_scalar(buf: &mut Vec<u8>, scalar: &Scalar) {
    buf.extend_from_slice(scalar.as_bytes());
}

fn write_var(buf: &mut Vec<u8>, data: &[u8]) -> Result<(), EncodingError> {
    let len: u16 = data
        .len()
        .try_into()
        .map_err(|_| EncodingError::TooLong)?;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
    Ok(())
}

fn read_point(data: &[u8], off: &mut usize) -> Result<RistrettoPoint, EncodingError> {
    if data.len() < *off + 32 {
        return Err(EncodingError::TooShort);
    }
    let pt = CompressedRistretto::from_slice(&data[*off..*off + 32])
        .map_err(|_| EncodingError::InvalidPoint)?
        .decompress()
        .ok_or(EncodingError::InvalidPoint)?;
    if pt == RistrettoPoint::identity() {
        return Err(EncodingError::InvalidPoint);
    }
    *off += 32;
    Ok(pt)
}

fn read_scalar(data: &[u8], off: &mut usize) -> Result<Scalar, EncodingError> {
    if data.len() < *off + 32 {
        return Err(EncodingError::TooShort);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&data[*off..*off + 32]);
    *off += 32;
    Option::from(Scalar::from_canonical_bytes(arr)).ok_or(EncodingError::InvalidScalar)
}

fn read_var(data: &[u8], off: &mut usize) -> Result<Vec<u8>, EncodingError> {
    if data.len() < *off + 2 {
        return Err(EncodingError::TooShort);
    }
    let len = u16::from_be_bytes([data[*off], data[*off + 1]]) as usize;
    *off += 2;
    if len < 1 {
        return Err(EncodingError::TooShort);
    }
    if data.len() < *off + len {
        return Err(EncodingError::TooShort);
    }
    let result = data[*off..*off + len].to_vec();
    *off += len;
    Ok(result)
}

fn check_exact(data: &[u8], off: usize) -> Result<(), EncodingError> {
    if off != data.len() {
        Err(EncodingError::TrailingData)
    } else {
        Ok(())
    }
}

// --- IssuanceRequest: K[32] || len(pok)[2] || pok[...] ---

impl IssuanceRequest {
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodingError> {
        let mut buf = Vec::new();
        write_point(&mut buf, &self.big_k);
        write_var(&mut buf, &self.pok)?;
        Ok(buf)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, EncodingError> {
        let mut off = 0;
        let big_k = read_point(data, &mut off)?;
        let pok = read_var(data, &mut off)?;
        check_exact(data, off)?;
        Ok(IssuanceRequest { big_k, pok })
    }
}

// --- IssuanceResponse: A[32] || e[32] || c[32] || ctx[32] || len(pok)[2] || pok[...] ---

impl IssuanceResponse {
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodingError> {
        let mut buf = Vec::new();
        write_point(&mut buf, &self.a);
        write_scalar(&mut buf, &self.e);
        write_scalar(&mut buf, &self.c);
        write_scalar(&mut buf, &self.ctx);
        write_var(&mut buf, &self.pok)?;
        Ok(buf)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, EncodingError> {
        let mut off = 0;
        let a = read_point(data, &mut off)?;
        let e = read_scalar(data, &mut off)?;
        let c = read_scalar(data, &mut off)?;
        let ctx = read_scalar(data, &mut off)?;
        let pok = read_var(data, &mut off)?;
        check_exact(data, off)?;
        Ok(IssuanceResponse { a, e, c, ctx, pok })
    }
}

// --- SpendProof: k[32] || s[32] || ctx[32] || A'[32] || B_bar[32] || Com[L*32] || len(pok)[2] || pok[...] ---

impl<const L: usize> SpendProof<L> {
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodingError> {
        let mut buf = Vec::with_capacity(5 * 32 + L * 32 + 2 + self.pok.len());
        write_scalar(&mut buf, &self.k);
        write_scalar(&mut buf, &self.s);
        write_scalar(&mut buf, &self.ctx);
        write_point(&mut buf, &self.a_prime);
        write_point(&mut buf, &self.b_bar);
        for com_j in &self.com {
            write_point(&mut buf, com_j);
        }
        write_var(&mut buf, &self.pok)?;
        Ok(buf)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, EncodingError> {
        let mut off = 0;
        let k = read_scalar(data, &mut off)?;
        let s = read_scalar(data, &mut off)?;
        let ctx = read_scalar(data, &mut off)?;
        let a_prime = read_point(data, &mut off)?;
        let b_bar = read_point(data, &mut off)?;
        let mut com = [RistrettoPoint::identity(); L];
        for j in 0..L {
            com[j] = read_point(data, &mut off)?;
        }
        let pok = read_var(data, &mut off)?;
        check_exact(data, off)?;
        Ok(SpendProof {
            k,
            s,
            ctx,
            a_prime,
            b_bar,
            com,
            pok,
        })
    }
}

// --- Refund: A*[32] || e*[32] || t[32] || len(pok)[2] || pok[...] ---

impl Refund {
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodingError> {
        let mut buf = Vec::new();
        write_point(&mut buf, &self.a);
        write_scalar(&mut buf, &self.e);
        write_scalar(&mut buf, &self.t);
        write_var(&mut buf, &self.pok)?;
        Ok(buf)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, EncodingError> {
        let mut off = 0;
        let a = read_point(data, &mut off)?;
        let e = read_scalar(data, &mut off)?;
        let t = read_scalar(data, &mut off)?;
        let pok = read_var(data, &mut off)?;
        check_exact(data, off)?;
        Ok(Refund { a, e, t, pok })
    }
}

// --- CreditToken: a[32] || e[32] || k[32] || r[32] || c[32] || ctx[32] = 192 bytes ---

impl CreditToken {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(192);
        write_point(&mut buf, &self.a);
        write_scalar(&mut buf, &self.e);
        write_scalar(&mut buf, &self.k);
        write_scalar(&mut buf, &self.r);
        write_scalar(&mut buf, &self.c);
        write_scalar(&mut buf, &self.ctx);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, EncodingError> {
        let mut off = 0;
        let a = read_point(data, &mut off)?;
        let e = read_scalar(data, &mut off)?;
        let k = read_scalar(data, &mut off)?;
        let r = read_scalar(data, &mut off)?;
        let c = read_scalar(data, &mut off)?;
        let ctx = read_scalar(data, &mut off)?;
        check_exact(data, off)?;
        Ok(CreditToken { a, e, k, r, c, ctx })
    }
}

// --- PreIssuance: r[32] || k[32] = 64 bytes ---

impl PreIssuance {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        write_scalar(&mut buf, &self.r);
        write_scalar(&mut buf, &self.k);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, EncodingError> {
        let mut off = 0;
        let r = read_scalar(data, &mut off)?;
        let k = read_scalar(data, &mut off)?;
        check_exact(data, off)?;
        Ok(PreIssuance { r, k })
    }
}

// --- PreRefund: r[32] || k[32] || m[32] || ctx[32] = 128 bytes ---

impl PreRefund {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        write_scalar(&mut buf, &self.r);
        write_scalar(&mut buf, &self.k);
        write_scalar(&mut buf, &self.m);
        write_scalar(&mut buf, &self.ctx);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, EncodingError> {
        let mut off = 0;
        let r = read_scalar(data, &mut off)?;
        let k = read_scalar(data, &mut off)?;
        let m = read_scalar(data, &mut off)?;
        let ctx = read_scalar(data, &mut off)?;
        check_exact(data, off)?;
        Ok(PreRefund { r, k, m, ctx })
    }
}

// --- PrivateKey: x[32] || w[32] = 64 bytes ---

impl PrivateKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        write_scalar(&mut buf, &self.x);
        write_point(&mut buf, &self.public.w);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, EncodingError> {
        let mut off = 0;
        let x = read_scalar(data, &mut off)?;
        let w = read_point(data, &mut off)?;
        check_exact(data, off)?;
        // Verify that the public key matches the secret scalar
        if w != RistrettoPoint::generator() * x {
            return Err(EncodingError::InvalidPoint);
        }
        Ok(PrivateKey {
            x,
            public: PublicKey { w },
        })
    }
}

// --- PublicKey: w[32] = 32 bytes ---

impl PublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.w.compress().as_bytes().to_vec()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, EncodingError> {
        let mut off = 0;
        let w = read_point(data, &mut off)?;
        check_exact(data, off)?;
        Ok(PublicKey { w })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use rand_core::OsRng;

    #[test]
    fn test_issuance_request_roundtrip() {
        let big_k = RistrettoPoint::random(&mut OsRng);
        let mut pok = vec![0; 64];
        OsRng.fill_bytes(&mut pok);

        let request = IssuanceRequest { big_k, pok };
        let bytes = request.to_bytes().unwrap();
        let decoded = IssuanceRequest::from_bytes(&bytes).unwrap();

        assert_eq!(request.big_k, decoded.big_k);
        assert_eq!(request.pok, decoded.pok);
    }

    #[test]
    fn test_issuance_response_roundtrip() {
        let a = RistrettoPoint::random(&mut OsRng);
        let e = Scalar::random(&mut OsRng);
        let c = Scalar::random(&mut OsRng);
        let ctx = Scalar::random(&mut OsRng);
        let mut pok = vec![0; 64];
        OsRng.fill_bytes(&mut pok);

        let response = IssuanceResponse { a, e, c, ctx, pok };
        let bytes = response.to_bytes().unwrap();
        let decoded = IssuanceResponse::from_bytes(&bytes).unwrap();

        assert_eq!(response.a, decoded.a);
        assert_eq!(response.e, decoded.e);
        assert_eq!(response.c, decoded.c);
        assert_eq!(response.ctx, decoded.ctx);
        assert_eq!(response.pok, decoded.pok);
    }

    #[test]
    fn test_refund_roundtrip() {
        let a = RistrettoPoint::random(&mut OsRng);
        let e = Scalar::random(&mut OsRng);
        let t = Scalar::random(&mut OsRng);
        let mut pok = vec![0; 64];
        OsRng.fill_bytes(&mut pok);

        let refund = Refund { a, e, t, pok };
        let bytes = refund.to_bytes().unwrap();
        let decoded = Refund::from_bytes(&bytes).unwrap();

        assert_eq!(refund.a, decoded.a);
        assert_eq!(refund.e, decoded.e);
        assert_eq!(refund.t, decoded.t);
        assert_eq!(refund.pok, decoded.pok);
    }

    #[test]
    fn test_private_key_roundtrip() {
        let private_key = PrivateKey::random(OsRng);
        let bytes = private_key.to_bytes();
        let decoded = PrivateKey::from_bytes(&bytes).unwrap();

        assert_eq!(private_key.x, decoded.x);
        assert_eq!(private_key.public.w, decoded.public.w);
    }

    #[test]
    fn test_private_key_mismatched_public_key() {
        let x = Scalar::random(&mut OsRng);
        let wrong_w = RistrettoPoint::random(&mut OsRng);
        // Manually serialize x || wrong_w
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(x.as_bytes());
        bytes.extend_from_slice(wrong_w.compress().as_bytes());
        assert_eq!(
            PrivateKey::from_bytes(&bytes).unwrap_err(),
            EncodingError::InvalidPoint
        );
    }

    #[test]
    fn test_public_key_roundtrip() {
        let w = RistrettoPoint::random(&mut OsRng);
        let public_key = PublicKey { w };

        let bytes = public_key.to_bytes();
        let decoded = PublicKey::from_bytes(&bytes).unwrap();

        assert_eq!(public_key.w, decoded.w);
    }

    #[test]
    fn test_pre_issuance_roundtrip() {
        let r = Scalar::random(&mut OsRng);
        let k = Scalar::random(&mut OsRng);

        let pre_issuance = PreIssuance { r, k };
        let bytes = pre_issuance.to_bytes();
        let decoded = PreIssuance::from_bytes(&bytes).unwrap();

        assert_eq!(pre_issuance.r, decoded.r);
        assert_eq!(pre_issuance.k, decoded.k);
    }

    #[test]
    fn test_credit_token_roundtrip() {
        let a = RistrettoPoint::random(&mut OsRng);
        let e = Scalar::random(&mut OsRng);
        let k = Scalar::random(&mut OsRng);
        let r = Scalar::random(&mut OsRng);
        let c = Scalar::random(&mut OsRng);
        let ctx = Scalar::random(&mut OsRng);

        let token = CreditToken { a, e, k, r, c, ctx };
        let bytes = token.to_bytes();
        let decoded = CreditToken::from_bytes(&bytes).unwrap();

        assert_eq!(token, decoded);
    }

    #[test]
    fn test_pre_refund_roundtrip() {
        let r = Scalar::random(&mut OsRng);
        let k = Scalar::random(&mut OsRng);
        let m = Scalar::random(&mut OsRng);
        let ctx = Scalar::random(&mut OsRng);

        let pre_refund = PreRefund { r, k, m, ctx };
        let bytes = pre_refund.to_bytes();
        let decoded = PreRefund::from_bytes(&bytes).unwrap();

        assert_eq!(pre_refund.r, decoded.r);
        assert_eq!(pre_refund.k, decoded.k);
        assert_eq!(pre_refund.m, decoded.m);
        assert_eq!(pre_refund.ctx, decoded.ctx);
    }

    #[test]
    fn test_truncated_data_errors() {
        // A valid public key is 32 bytes; truncated should fail
        let w = RistrettoPoint::random(&mut OsRng);
        let bytes = PublicKey { w }.to_bytes();
        assert!(PublicKey::from_bytes(&bytes[..31]).is_err());
    }

    #[test]
    fn test_trailing_data_errors() {
        let w = RistrettoPoint::random(&mut OsRng);
        let mut bytes = PublicKey { w }.to_bytes();
        bytes.push(0xFF);
        assert_eq!(
            PublicKey::from_bytes(&bytes).unwrap_err(),
            EncodingError::TrailingData
        );
    }

    #[test]
    fn test_fixed_sizes() {
        // Verify expected byte sizes for fixed-length types
        let token = CreditToken {
            a: RistrettoPoint::random(&mut OsRng),
            e: Scalar::random(&mut OsRng),
            k: Scalar::random(&mut OsRng),
            r: Scalar::random(&mut OsRng),
            c: Scalar::random(&mut OsRng),
            ctx: Scalar::random(&mut OsRng),
        };
        assert_eq!(token.to_bytes().len(), 192);

        let pre_issuance = PreIssuance {
            r: Scalar::random(&mut OsRng),
            k: Scalar::random(&mut OsRng),
        };
        assert_eq!(pre_issuance.to_bytes().len(), 64);

        let pre_refund = PreRefund {
            r: Scalar::random(&mut OsRng),
            k: Scalar::random(&mut OsRng),
            m: Scalar::random(&mut OsRng),
            ctx: Scalar::random(&mut OsRng),
        };
        assert_eq!(pre_refund.to_bytes().len(), 128);

        let private_key = PrivateKey::random(OsRng);
        assert_eq!(private_key.to_bytes().len(), 64);

        let public_key = private_key.public().clone();
        assert_eq!(public_key.to_bytes().len(), 32);
    }
}
