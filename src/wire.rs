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

//! Wire format for Anonymous Credit Token protocol messages.
//!
//! This module implements the wire format from the "Protocol Messages and
//! Wire Format" section of draft-schlesinger-cfrg-act, which uses the TLS
//! presentation language (Section 3 of RFC 8446): fixed-width 32-byte
//! encodings for scalars and compressed Ristretto points, and a 2-byte
//! big-endian length prefix for the variable-length `pok` field
//! (`opaque pok<1..2^16-1>`).
//!
//! Message sizes for the ACT(ristretto255, SHAKE128) suite (Ne = Ns = 32):
//!
//! | Message             | Size            |
//! |---------------------|-----------------|
//! | IssuanceRequestMsg  | 130 bytes       |
//! | IssuanceResponseMsg | 162 bytes       |
//! | SpendProofMsg       | 384*D + 482     |
//! | RefundMsg           | 162 bytes       |
//!
//! Client storage types (CreditToken, PreIssuance, PreRefund) and keys use
//! fixed-width concatenations of their fields; these are local encodings,
//! not protocol messages.

use crate::{
    CreditToken, IssuanceRequest, IssuanceResponse, PreIssuance, PreRefund, PrivateKey,
    PublicKey, Refund, SpendProof,
};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::{RistrettoPoint, Scalar};
use group::Group;

/// Error type for wire format serialization/deserialization
#[derive(Debug, PartialEq)]
pub enum WireError {
    /// The input is shorter than the message requires
    TooShort,
    /// The input has bytes beyond the end of the message
    TrailingBytes,
    /// A point failed to decode, or decoded to the identity element
    InvalidPoint,
    /// A scalar encoding was non-canonical
    InvalidScalar,
    /// The pok length prefix is zero or inconsistent with the input
    InvalidLength,
}

const NE: usize = 32;
const NS: usize = 32;

/// The exact wire size of IssuanceRequestMsg: Ne + 3*Ns + 2.
pub const ISSUANCE_REQUEST_SIZE: usize = 130;
/// The exact wire size of IssuanceResponseMsg: Ne + 4*Ns + 2.
pub const ISSUANCE_RESPONSE_SIZE: usize = 162;
/// The exact wire size of SpendProofMsg for a given digit count D:
/// (4D+3)*Ne + (8D+12)*Ns + 2.
pub const fn spend_proof_size(d: usize) -> usize {
    384 * d + 482
}
/// The exact wire size of RefundMsg: Ne + 4*Ns + 2.
pub const REFUND_SIZE: usize = 162;

/// A cursor over an input buffer that reads fixed-width fields.
struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.buf.len() < n {
            return Err(WireError::TooShort);
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    /// Reads a compressed Ristretto point, rejecting invalid encodings and
    /// the identity element (see "Point Validation" in the draft).
    fn point(&mut self) -> Result<RistrettoPoint, WireError> {
        let bytes = self.take(NE)?;
        let point = CompressedRistretto::from_slice(bytes)
            .map_err(|_| WireError::InvalidPoint)?
            .decompress()
            .ok_or(WireError::InvalidPoint)?;
        if point == RistrettoPoint::identity() {
            return Err(WireError::InvalidPoint);
        }
        Ok(point)
    }

    /// Reads a canonically encoded scalar.
    fn scalar(&mut self) -> Result<Scalar, WireError> {
        let bytes: [u8; NS] = self.take(NS)?.try_into().expect("fixed width");
        Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes)).ok_or(WireError::InvalidScalar)
    }

    /// Reads a 2-byte big-endian length-prefixed pok field.
    fn pok(&mut self) -> Result<Vec<u8>, WireError> {
        let len_bytes = self.take(2)?;
        let len = u16::from_be_bytes(len_bytes.try_into().expect("fixed width")) as usize;
        if len == 0 {
            return Err(WireError::InvalidLength);
        }
        Ok(self.take(len)?.to_vec())
    }

    fn finish(&self) -> Result<(), WireError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(WireError::TrailingBytes)
        }
    }
}

fn put_point(out: &mut Vec<u8>, point: &RistrettoPoint) {
    out.extend_from_slice(point.compress().as_bytes());
}

fn put_scalar(out: &mut Vec<u8>, scalar: &Scalar) {
    out.extend_from_slice(scalar.as_bytes());
}

fn put_pok(out: &mut Vec<u8>, pok: &[u8]) {
    debug_assert!(!pok.is_empty() && pok.len() <= u16::MAX as usize);
    out.extend_from_slice(&(pok.len() as u16).to_be_bytes());
    out.extend_from_slice(pok);
}

impl IssuanceRequest {
    /// Encodes this message as an IssuanceRequestMsg:
    ///
    /// ```text
    /// struct {
    ///     opaque K[Ne];
    ///     opaque pok<1..2^16-1>;
    /// } IssuanceRequestMsg;
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ISSUANCE_REQUEST_SIZE);
        put_point(&mut out, &self.big_k);
        put_pok(&mut out, &self.pok);
        out
    }

    /// Decodes an IssuanceRequestMsg.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let big_k = r.point()?;
        let pok = r.pok()?;
        r.finish()?;
        Ok(IssuanceRequest { big_k, pok })
    }
}

impl IssuanceResponse {
    /// Encodes this message as an IssuanceResponseMsg:
    ///
    /// ```text
    /// struct {
    ///     opaque A[Ne];
    ///     opaque e[Ns];
    ///     opaque c[Ns];
    ///     opaque pok<1..2^16-1>;
    /// } IssuanceResponseMsg;
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ISSUANCE_RESPONSE_SIZE);
        put_point(&mut out, &self.a);
        put_scalar(&mut out, &self.e);
        put_scalar(&mut out, &self.c);
        put_pok(&mut out, &self.pok);
        out
    }

    /// Decodes an IssuanceResponseMsg.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let a = r.point()?;
        let e = r.scalar()?;
        let c = r.scalar()?;
        let pok = r.pok()?;
        r.finish()?;
        Ok(IssuanceResponse { a, e, c, pok })
    }
}

impl<const D: usize> SpendProof<D> {
    /// Encodes this message as a SpendProofMsg:
    ///
    /// ```text
    /// struct {
    ///     opaque k[Ns];
    ///     opaque s[Ns];
    ///     opaque a[Ns];
    ///     opaque ctx[Ns];
    ///     opaque A_prime[Ne];
    ///     opaque B_bar[Ne];
    ///     opaque Com1[D][Ne];
    ///     opaque T1[D][Ne];
    ///     opaque Com2[D][Ne];
    ///     opaque T2[D][Ne];
    ///     opaque K_n[Ne];
    ///     opaque pok<1..2^16-1>;
    /// } SpendProofMsg;
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(spend_proof_size(D));
        put_scalar(&mut out, &self.k);
        put_scalar(&mut out, &self.s);
        put_scalar(&mut out, &self.a);
        put_scalar(&mut out, &self.ctx);
        put_point(&mut out, &self.a_prime);
        put_point(&mut out, &self.b_bar);
        for com in self.com1.iter() {
            put_point(&mut out, com);
        }
        for t in self.t1.iter() {
            put_point(&mut out, t);
        }
        for com in self.com2.iter() {
            put_point(&mut out, com);
        }
        for t in self.t2.iter() {
            put_point(&mut out, t);
        }
        put_point(&mut out, &self.k_n);
        put_pok(&mut out, &self.pok);
        out
    }

    /// Decodes a SpendProofMsg.
    ///
    /// Note that this rejects an identity A_prime during point validation;
    /// the issuer's IdentityPointError check in refund processing covers
    /// proofs constructed in memory.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        const { assert!(D >= 1 && D <= crate::MAX_DIGITS, "D must be in 1..=MAX_DIGITS") };
        let mut r = Reader::new(bytes);
        let k = r.scalar()?;
        let s = r.scalar()?;
        let a = r.scalar()?;
        let ctx = r.scalar()?;
        let a_prime = r.point()?;
        let b_bar = r.point()?;
        let mut com1 = [RistrettoPoint::identity(); D];
        for c in com1.iter_mut() {
            *c = r.point()?;
        }
        let mut t1 = [RistrettoPoint::identity(); D];
        for t_j in t1.iter_mut() {
            *t_j = r.point()?;
        }
        let mut com2 = [RistrettoPoint::identity(); D];
        for c in com2.iter_mut() {
            *c = r.point()?;
        }
        let mut t2 = [RistrettoPoint::identity(); D];
        for t_j in t2.iter_mut() {
            *t_j = r.point()?;
        }
        let k_n = r.point()?;
        let pok = r.pok()?;
        r.finish()?;
        Ok(SpendProof {
            k,
            s,
            a,
            ctx,
            a_prime,
            b_bar,
            com1,
            t1,
            com2,
            t2,
            k_n,
            pok,
        })
    }
}

impl Refund {
    /// Encodes this message as a RefundMsg:
    ///
    /// ```text
    /// struct {
    ///     opaque A_star[Ne];
    ///     opaque e_star[Ns];
    ///     opaque t[Ns];
    ///     opaque pok<1..2^16-1>;
    /// } RefundMsg;
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(REFUND_SIZE);
        put_point(&mut out, &self.a);
        put_scalar(&mut out, &self.e);
        put_scalar(&mut out, &self.t);
        put_pok(&mut out, &self.pok);
        out
    }

    /// Decodes a RefundMsg.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let a = r.point()?;
        let e = r.scalar()?;
        let t = r.scalar()?;
        let pok = r.pok()?;
        r.finish()?;
        Ok(Refund { a, e, t, pok })
    }
}

impl CreditToken {
    /// Encodes this token for client storage as the concatenation
    /// `A || e || k || r || c || ctx` (Ne + 5*Ns = 192 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(192);
        put_point(&mut out, &self.a);
        put_scalar(&mut out, &self.e);
        put_scalar(&mut out, &self.k);
        put_scalar(&mut out, &self.r);
        put_scalar(&mut out, &self.c);
        put_scalar(&mut out, &self.ctx);
        out
    }

    /// Decodes a stored token.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let mut rd = Reader::new(bytes);
        let a = rd.point()?;
        let e = rd.scalar()?;
        let k = rd.scalar()?;
        let r = rd.scalar()?;
        let c = rd.scalar()?;
        let ctx = rd.scalar()?;
        rd.finish()?;
        Ok(CreditToken { a, e, k, r, c, ctx })
    }
}

impl PreIssuance {
    /// Encodes this state for client storage as `r || k` (64 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        put_scalar(&mut out, &self.r);
        put_scalar(&mut out, &self.k);
        out
    }

    /// Decodes stored pre-issuance state.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let mut rd = Reader::new(bytes);
        let r = rd.scalar()?;
        let k = rd.scalar()?;
        rd.finish()?;
        Ok(PreIssuance { r, k })
    }
}

impl PreRefund {
    /// Encodes this state for client storage as `r || k || v || ctx`
    /// (128 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        put_scalar(&mut out, &self.r);
        put_scalar(&mut out, &self.k);
        put_scalar(&mut out, &self.v);
        put_scalar(&mut out, &self.ctx);
        out
    }

    /// Decodes stored pre-refund state.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let mut rd = Reader::new(bytes);
        let r = rd.scalar()?;
        let k = rd.scalar()?;
        let v = rd.scalar()?;
        let ctx = rd.scalar()?;
        rd.finish()?;
        Ok(PreRefund { r, k, v, ctx })
    }
}

impl PrivateKey {
    /// Encodes the private key as the scalar `x` (32 bytes). The public
    /// key is rederived on decode.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.x.as_bytes().to_vec()
    }

    /// Decodes a private key, rederiving the public key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let x = r.scalar()?;
        r.finish()?;
        Ok(PrivateKey {
            x,
            public: PublicKey {
                w: RistrettoPoint::generator() * x,
            },
        })
    }
}

impl PublicKey {
    /// Encodes the public key as a compressed point (32 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.w.compress().as_bytes().to_vec()
    }

    /// Decodes a public key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let w = r.point()?;
        r.finish()?;
        Ok(PublicKey { w })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    const D: usize = 8;

    fn setup() -> (crate::Params<D>, PrivateKey, CreditToken) {
        let params = crate::Params::new("wire-org", "wire-svc", "test", "2024-01-01");
        let private_key = PrivateKey::random(OsRng);
        let pre = PreIssuance::random(OsRng);
        let request = pre.request(&params, OsRng);
        let ctx = Scalar::from(7u64);
        let response = private_key
            .issue(&params, &request, 100, ctx, OsRng)
            .unwrap();
        let token = pre
            .to_credit_token(&params, private_key.public(), &request, &response, ctx)
            .unwrap();
        (params, private_key, token)
    }

    /// The four protocol messages have exactly the sizes given in the
    /// draft's performance table, and roundtrip through the wire format.
    #[test]
    fn test_message_sizes_and_roundtrips() {
        let params: crate::Params<D> =
            crate::Params::new("wire-org", "wire-svc", "test", "2024-01-01");
        let private_key = PrivateKey::random(OsRng);
        let pre = PreIssuance::random(OsRng);
        let ctx = Scalar::from(7u64);

        let request = pre.request(&params, OsRng);
        let request_bytes = request.to_bytes();
        assert_eq!(request_bytes.len(), ISSUANCE_REQUEST_SIZE);
        let request2 = IssuanceRequest::from_bytes(&request_bytes).unwrap();
        assert_eq!(request.big_k, request2.big_k);
        assert_eq!(request.pok, request2.pok);

        let response = private_key
            .issue(&params, &request, 100, ctx, OsRng)
            .unwrap();
        let response_bytes = response.to_bytes();
        assert_eq!(response_bytes.len(), ISSUANCE_RESPONSE_SIZE);
        let response2 = IssuanceResponse::from_bytes(&response_bytes).unwrap();
        assert_eq!(response, response2);

        let token = pre
            .to_credit_token(&params, private_key.public(), &request, &response2, ctx)
            .unwrap();
        let (spend_proof, prerefund) = token.prove_spend(&params, 30, 5, OsRng).unwrap();
        let spend_bytes = spend_proof.to_bytes();
        assert_eq!(spend_bytes.len(), spend_proof_size(D));
        let spend_proof2 = SpendProof::<D>::from_bytes(&spend_bytes).unwrap();

        // The decoded proof still verifies and refunds correctly.
        let refund = private_key
            .refund(&params, &spend_proof2, 10, OsRng)
            .unwrap();
        let refund_bytes = refund.to_bytes();
        assert_eq!(refund_bytes.len(), REFUND_SIZE);
        let refund2 = Refund::from_bytes(&refund_bytes).unwrap();
        assert_eq!(refund, refund2);

        let new_token = prerefund
            .to_credit_token(&params, &spend_proof2, &refund2, private_key.public())
            .unwrap();
        // 100 - 30 + 10 = 80 (the return amount t = 10 grants part of the
        // authorized top-up of 5 plus 5 refunded credits).
        assert_eq!(new_token.credits(), Scalar::from(80u64));
    }

    #[test]
    fn test_storage_roundtrips() {
        let (_, private_key, token) = setup();

        let token_bytes = token.to_bytes();
        assert_eq!(token_bytes.len(), 192);
        assert_eq!(CreditToken::from_bytes(&token_bytes).unwrap(), token);

        let pre = PreIssuance::random(OsRng);
        let pre2 = PreIssuance::from_bytes(&pre.to_bytes()).unwrap();
        assert_eq!(pre.r, pre2.r);
        assert_eq!(pre.k, pre2.k);

        let prerefund = PreRefund {
            r: Scalar::from(1u64),
            k: Scalar::from(2u64),
            v: Scalar::from(3u64),
            ctx: Scalar::from(4u64),
        };
        let prerefund2 = PreRefund::from_bytes(&prerefund.to_bytes()).unwrap();
        assert_eq!(prerefund.r, prerefund2.r);
        assert_eq!(prerefund.k, prerefund2.k);
        assert_eq!(prerefund.v, prerefund2.v);
        assert_eq!(prerefund.ctx, prerefund2.ctx);

        let key2 = PrivateKey::from_bytes(&private_key.to_bytes()).unwrap();
        assert_eq!(private_key.x, key2.x);
        assert_eq!(private_key.public.w, key2.public.w);

        let pk2 = PublicKey::from_bytes(&private_key.public().to_bytes()).unwrap();
        assert_eq!(private_key.public.w, pk2.w);
    }

    #[test]
    fn test_malformed_inputs_rejected() {
        let (params, private_key, token) = setup();
        let (spend_proof, _) = token.prove_spend(&params, 10, 0, OsRng).unwrap();
        let bytes = spend_proof.to_bytes();

        // Truncated input.
        assert_eq!(
            SpendProof::<D>::from_bytes(&bytes[..bytes.len() - 1]).err(),
            Some(WireError::TooShort)
        );
        // Trailing bytes.
        let mut extended = bytes.clone();
        extended.push(0);
        assert_eq!(
            SpendProof::<D>::from_bytes(&extended).err(),
            Some(WireError::TrailingBytes)
        );
        // Identity point (32 zero bytes) in A_prime's position.
        let mut identity_point = bytes.clone();
        identity_point[128..160].fill(0);
        assert_eq!(
            SpendProof::<D>::from_bytes(&identity_point).err(),
            Some(WireError::InvalidPoint)
        );
        // Non-canonical scalar (order + 1 <=> all-ones high bits) for k.
        let mut bad_scalar = bytes.clone();
        bad_scalar[0..32].fill(0xff);
        assert_eq!(
            SpendProof::<D>::from_bytes(&bad_scalar).err(),
            Some(WireError::InvalidScalar)
        );
        // Zero-length pok.
        let refund = private_key.refund(&params, &spend_proof, 0, OsRng).unwrap();
        let mut refund_bytes = refund.to_bytes();
        refund_bytes.truncate(96);
        refund_bytes.extend_from_slice(&[0, 0]);
        assert_eq!(
            Refund::from_bytes(&refund_bytes).err(),
            Some(WireError::InvalidLength)
        );
    }
}
