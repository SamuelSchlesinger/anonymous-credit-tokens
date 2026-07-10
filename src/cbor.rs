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

//! CBOR serialization for Anonymous Credit Token protocol messages.
//!
//! This module implements the CBOR wire format as specified in the IETF draft.
//! All protocol messages are encoded using deterministic CBOR (RFC 8949) for
//! interoperability.

use crate::{
    CreditToken, D, IssuanceRequest, IssuanceResponse, PreIssuance, PreRefund, PrivateKey,
    PublicKey, Refund, SpendProof,
};
use ciborium::value::Value;
use curve25519_dalek::{RistrettoPoint, Scalar};

/// Error type for CBOR serialization/deserialization
#[derive(Debug)]
pub enum CborError {
    /// Error from ciborium library
    Ciborium(ciborium::de::Error<std::io::Error>),
    /// Invalid CBOR structure
    InvalidStructure(&'static str),
    /// Invalid field value
    InvalidValue(&'static str),
}

impl From<ciborium::de::Error<std::io::Error>> for CborError {
    fn from(e: ciborium::de::Error<std::io::Error>) -> Self {
        CborError::Ciborium(e)
    }
}

impl From<ciborium::ser::Error<std::io::Error>> for CborError {
    fn from(_: ciborium::ser::Error<std::io::Error>) -> Self {
        CborError::InvalidStructure("serialization error")
    }
}

/// Encode a RistrettoPoint as a 32-byte CBOR byte string
fn encode_point(point: &RistrettoPoint) -> Value {
    Value::Bytes(point.compress().as_bytes().to_vec())
}

/// Encode a Scalar as a 32-byte CBOR byte string (little-endian)
fn encode_scalar(scalar: &Scalar) -> Value {
    Value::Bytes(scalar.as_bytes().to_vec())
}

/// Encode a byte slice as a CBOR byte string
fn encode_vec(v: &[u8]) -> Value {
    Value::Bytes(v.to_vec())
}

/// Decode a RistrettoPoint from a CBOR byte string
fn decode_point(value: &Value) -> Result<RistrettoPoint, CborError> {
    match value {
        Value::Bytes(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            use curve25519_dalek::ristretto::CompressedRistretto;
            CompressedRistretto::from_slice(&arr)
                .unwrap()
                .decompress()
                .ok_or(CborError::InvalidValue("invalid Ristretto point"))
        }
        _ => Err(CborError::InvalidStructure(
            "expected 32-byte array for point",
        )),
    }
}

/// Decode a Scalar from a CBOR byte string (little-endian)
fn decode_scalar(value: &Value) -> Result<Scalar, CborError> {
    match value {
        Value::Bytes(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            Ok(Scalar::from_bytes_mod_order(arr))
        }
        _ => Err(CborError::InvalidStructure(
            "expected 32-byte array for scalar",
        )),
    }
}

/// Decode a `Vec<u8>` from a CBOR byte string
fn decode_vec(value: &Value) -> Result<Vec<u8>, CborError> {
    match value {
        Value::Bytes(bytes) => Ok(bytes.clone()),
        _ => Err(CborError::InvalidStructure("expected byte array")),
    }
}

/// CBOR encoding for IssuanceRequest
impl IssuanceRequest {
    /// Encode to CBOR according to spec format:
    /// ```text
    /// IssuanceRequestMsg = {
    ///     1: bstr,  ; K (compressed Ristretto point, 32 bytes)
    ///     2: bstr   ; pok (bytes, n bytes)
    /// }
    /// ```
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let map = vec![
            (Value::Integer(1.into()), encode_point(&self.big_k)),
            (Value::Integer(2.into()), encode_vec(&self.pok)),
        ];

        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut bytes)?;
        Ok(bytes)
    }

    /// Decode from CBOR
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let value: Value = ciborium::from_reader(bytes)?;

        match value {
            Value::Map(map) => {
                let mut big_k = None;
                let mut pok = None;

                for (k, v) in map {
                    match k {
                        Value::Integer(i) if i == 1.into() => big_k = Some(decode_point(&v)?),
                        Value::Integer(i) if i == 2.into() => pok = Some(decode_vec(&v)?),
                        _ => {}
                    }
                }

                Ok(IssuanceRequest {
                    big_k: big_k.ok_or(CborError::InvalidStructure("missing field 1 (K)"))?,
                    pok: pok.ok_or(CborError::InvalidStructure("missing field 2 (pok)"))?,
                })
            }
            _ => Err(CborError::InvalidStructure("expected CBOR map")),
        }
    }
}

/// CBOR encoding for IssuanceResponse
impl IssuanceResponse {
    /// Encode to CBOR according to spec format:
    /// ```text
    /// IssuanceResponseMsg = {
    ///     1: bstr,  ; A (compressed Ristretto point, 32 bytes)
    ///     2: bstr,  ; e (scalar, 32 bytes)
    ///     3: bstr,  ; c (scalar, 32 bytes)
    ///     4: bstr,  ; pok (bytes, n bytes)
    /// }
    /// ```
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let map = vec![
            (Value::Integer(1.into()), encode_point(&self.a)),
            (Value::Integer(2.into()), encode_scalar(&self.e)),
            (Value::Integer(3.into()), encode_scalar(&self.c)),
            (Value::Integer(4.into()), encode_vec(&self.pok)),
        ];

        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut bytes)?;
        Ok(bytes)
    }

    /// Decode from CBOR
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let value: Value = ciborium::from_reader(bytes)?;

        match value {
            Value::Map(map) => {
                let mut a = None;
                let mut e = None;
                let mut c = None;
                let mut pok = None;

                for (k, v) in map {
                    match k {
                        Value::Integer(i) if i == 1.into() => a = Some(decode_point(&v)?),
                        Value::Integer(i) if i == 2.into() => e = Some(decode_scalar(&v)?),
                        Value::Integer(i) if i == 3.into() => c = Some(decode_scalar(&v)?),
                        Value::Integer(i) if i == 4.into() => pok = Some(decode_vec(&v)?),
                        _ => {}
                    }
                }

                Ok(IssuanceResponse {
                    a: a.ok_or(CborError::InvalidStructure("missing field 1 (A)"))?,
                    e: e.ok_or(CborError::InvalidStructure("missing field 2 (e)"))?,
                    c: c.ok_or(CborError::InvalidStructure("missing field 3 (c)"))?,
                    pok: pok.ok_or(CborError::InvalidStructure("missing field 4 (pok)"))?,
                })
            }
            _ => Err(CborError::InvalidStructure("expected CBOR map")),
        }
    }
}

/// CBOR encoding for SpendProof
/// Decodes a CBOR array of exactly D compressed points.
fn decode_point_array(value: Value, what: &'static str) -> Result<[RistrettoPoint; D], CborError> {
    if let Value::Array(arr) = value {
        let points: Result<Vec<_>, _> = arr.into_iter().map(|v| decode_point(&v)).collect();
        let points = points?;
        if points.len() == D {
            use group::Group;
            let mut fixed = [RistrettoPoint::identity(); D];
            fixed.copy_from_slice(&points);
            Ok(fixed)
        } else {
            Err(CborError::InvalidStructure(what))
        }
    } else {
        Err(CborError::InvalidStructure(what))
    }
}

impl SpendProof {
    /// Encode to CBOR according to spec format:
    /// ```text
    /// SpendProofMsg = {
    ///     1: bstr,      ; k (nullifier, 32 bytes)
    ///     2: bstr,      ; s (spend amount, 32 bytes)
    ///     3: bstr,      ; a (top-up amount, 32 bytes)
    ///     4: bstr,      ; ctx (request context, 32 bytes)
    ///     5: bstr,      ; A' (compressed point, 32 bytes)
    ///     6: bstr,      ; B_bar (compressed point, 32 bytes)
    ///     7: [* bstr],  ; Com array (D compressed points)
    ///     8: [* bstr],  ; T array (D compressed points)
    ///     9: bstr       ; pok (compact sigma protocol proof)
    /// }
    /// ```
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let com_array: Vec<Value> = self.com.iter().map(encode_point).collect();
        let t_array: Vec<Value> = self.t.iter().map(encode_point).collect();

        let map = vec![
            (Value::Integer(1.into()), encode_scalar(&self.k)),
            (Value::Integer(2.into()), encode_scalar(&self.s)),
            (Value::Integer(3.into()), encode_scalar(&self.a)),
            (Value::Integer(4.into()), encode_scalar(&self.ctx)),
            (Value::Integer(5.into()), encode_point(&self.a_prime)),
            (Value::Integer(6.into()), encode_point(&self.b_bar)),
            (Value::Integer(7.into()), Value::Array(com_array)),
            (Value::Integer(8.into()), Value::Array(t_array)),
            (Value::Integer(9.into()), encode_vec(&self.pok)),
        ];

        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut bytes)?;
        Ok(bytes)
    }

    /// Decode from CBOR
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let value: Value = ciborium::from_reader(bytes)?;

        match value {
            Value::Map(map) => {
                let mut k = None;
                let mut s = None;
                let mut a = None;
                let mut ctx = None;
                let mut a_prime = None;
                let mut b_bar = None;
                let mut com = None;
                let mut t = None;
                let mut pok = None;

                for (key, val) in map {
                    match key {
                        Value::Integer(i) if i == 1.into() => k = Some(decode_scalar(&val)?),
                        Value::Integer(i) if i == 2.into() => s = Some(decode_scalar(&val)?),
                        Value::Integer(i) if i == 3.into() => a = Some(decode_scalar(&val)?),
                        Value::Integer(i) if i == 4.into() => ctx = Some(decode_scalar(&val)?),
                        Value::Integer(i) if i == 5.into() => a_prime = Some(decode_point(&val)?),
                        Value::Integer(i) if i == 6.into() => b_bar = Some(decode_point(&val)?),
                        Value::Integer(i) if i == 7.into() => {
                            com = Some(decode_point_array(val, "Com array wrong size")?)
                        }
                        Value::Integer(i) if i == 8.into() => {
                            t = Some(decode_point_array(val, "T array wrong size")?)
                        }
                        Value::Integer(i) if i == 9.into() => pok = Some(decode_vec(&val)?),
                        _ => {}
                    }
                }

                Ok(SpendProof {
                    k: k.ok_or(CborError::InvalidStructure("missing field 1"))?,
                    s: s.ok_or(CborError::InvalidStructure("missing field 2"))?,
                    a: a.ok_or(CborError::InvalidStructure("missing field 3"))?,
                    ctx: ctx.ok_or(CborError::InvalidStructure("missing field 4"))?,
                    a_prime: a_prime.ok_or(CborError::InvalidStructure("missing field 5"))?,
                    b_bar: b_bar.ok_or(CborError::InvalidStructure("missing field 6"))?,
                    com: com.ok_or(CborError::InvalidStructure("missing field 7"))?,
                    t: t.ok_or(CborError::InvalidStructure("missing field 8"))?,
                    pok: pok.ok_or(CborError::InvalidStructure("missing field 9"))?,
                })
            }
            _ => Err(CborError::InvalidStructure("expected CBOR map")),
        }
    }
}

/// CBOR encoding for Refund
impl Refund {
    /// Encode to CBOR according to spec format:
    /// ```text
    /// RefundMsg = {
    ///     1: bstr,  ; A* (compressed Ristretto point, 32 bytes)
    ///     2: bstr,  ; e* (scalar, 32 bytes)
    ///     3: bstr,  ; t (partial refund amount, 32 bytes)
    ///     4: bstr,  ; pok (bytes, n bytes)
    /// }
    /// ```
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let map = vec![
            (Value::Integer(1.into()), encode_point(&self.a)),
            (Value::Integer(2.into()), encode_scalar(&self.e)),
            (Value::Integer(3.into()), encode_scalar(&self.t)),
            (Value::Integer(4.into()), encode_vec(&self.pok)),
        ];

        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut bytes)?;
        Ok(bytes)
    }

    /// Decode from CBOR
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let value: Value = ciborium::from_reader(bytes)?;

        match value {
            Value::Map(map) => {
                let mut a = None;
                let mut e = None;
                let mut t = None;
                let mut pok = None;

                for (k, v) in map {
                    match k {
                        Value::Integer(i) if i == 1.into() => a = Some(decode_point(&v)?),
                        Value::Integer(i) if i == 2.into() => e = Some(decode_scalar(&v)?),
                        Value::Integer(i) if i == 3.into() => t = Some(decode_scalar(&v)?),
                        Value::Integer(i) if i == 4.into() => pok = Some(decode_vec(&v)?),
                        _ => {}
                    }
                }

                Ok(Refund {
                    a: a.ok_or(CborError::InvalidStructure("missing field 1 (A*)"))?,
                    e: e.ok_or(CborError::InvalidStructure("missing field 2 (e*)"))?,
                    t: t.ok_or(CborError::InvalidStructure("missing field 3 (t)"))?,
                    pok: pok.ok_or(CborError::InvalidStructure("missing field 4 (pok)"))?,
                })
            }
            _ => Err(CborError::InvalidStructure("expected CBOR map")),
        }
    }
}

/// CBOR encoding for PrivateKey
impl PrivateKey {
    /// Encode to CBOR according to format:
    /// ```text
    /// PrivateKey = {
    ///     1: bstr,  ; x (scalar, 32 bytes)
    ///     2: bstr   ; w (public key point, 32 bytes)
    /// }
    /// ```
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let map = vec![
            (Value::Integer(1.into()), encode_scalar(&self.x)),
            (Value::Integer(2.into()), encode_point(&self.public.w)),
        ];

        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut bytes)?;
        Ok(bytes)
    }

    /// Decode from CBOR
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let value: Value = ciborium::from_reader(bytes)?;

        match value {
            Value::Map(map) => {
                let mut x = None;
                let mut w = None;

                for (k, v) in map {
                    match k {
                        Value::Integer(i) if i == 1.into() => x = Some(decode_scalar(&v)?),
                        Value::Integer(i) if i == 2.into() => w = Some(decode_point(&v)?),
                        _ => {}
                    }
                }

                Ok(PrivateKey {
                    x: x.ok_or(CborError::InvalidStructure("missing field 1 (x)"))?,
                    public: PublicKey {
                        w: w.ok_or(CborError::InvalidStructure("missing field 2 (w)"))?,
                    },
                })
            }
            _ => Err(CborError::InvalidStructure("expected CBOR map")),
        }
    }
}

/// CBOR encoding for PublicKey
impl PublicKey {
    /// Encode to CBOR according to format:
    /// ```text
    /// PublicKey = bstr  ; w (compressed Ristretto point, 32 bytes)
    /// ```
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let mut bytes = Vec::new();
        ciborium::into_writer(&encode_point(&self.w), &mut bytes)?;
        Ok(bytes)
    }

    /// Decode from CBOR
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let value: Value = ciborium::from_reader(bytes)?;
        let w = decode_point(&value)?;
        Ok(PublicKey { w })
    }
}

/// CBOR encoding for PreIssuance
impl PreIssuance {
    /// Encode to CBOR according to format:
    /// ```text
    /// PreIssuance = {
    ///     1: bstr,  ; r (scalar, 32 bytes)
    ///     2: bstr   ; k (scalar, 32 bytes)
    /// }
    /// ```
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let map = vec![
            (Value::Integer(1.into()), encode_scalar(&self.r)),
            (Value::Integer(2.into()), encode_scalar(&self.k)),
        ];

        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut bytes)?;
        Ok(bytes)
    }

    /// Decode from CBOR
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let value: Value = ciborium::from_reader(bytes)?;

        match value {
            Value::Map(map) => {
                let mut r = None;
                let mut k = None;

                for (key, val) in map {
                    match key {
                        Value::Integer(i) if i == 1.into() => r = Some(decode_scalar(&val)?),
                        Value::Integer(i) if i == 2.into() => k = Some(decode_scalar(&val)?),
                        _ => {}
                    }
                }

                Ok(PreIssuance {
                    r: r.ok_or(CborError::InvalidStructure("missing field 1 (r)"))?,
                    k: k.ok_or(CborError::InvalidStructure("missing field 2 (k)"))?,
                })
            }
            _ => Err(CborError::InvalidStructure("expected CBOR map")),
        }
    }
}

/// CBOR encoding for CreditToken
impl CreditToken {
    /// Encode to CBOR according to format:
    /// ```text
    /// CreditToken = {
    ///     1: bstr,  ; a (compressed Ristretto point, 32 bytes)
    ///     2: bstr,  ; e (scalar, 32 bytes)
    ///     3: bstr,  ; k (scalar, 32 bytes)
    ///     4: bstr,  ; r (scalar, 32 bytes)
    ///     5: bstr,  ; c (scalar, 32 bytes)
    ///     6: bstr   ; ctx (scalar, 32 bytes)
    /// }
    /// ```
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let map = vec![
            (Value::Integer(1.into()), encode_point(&self.a)),
            (Value::Integer(2.into()), encode_scalar(&self.e)),
            (Value::Integer(3.into()), encode_scalar(&self.k)),
            (Value::Integer(4.into()), encode_scalar(&self.r)),
            (Value::Integer(5.into()), encode_scalar(&self.c)),
            (Value::Integer(6.into()), encode_scalar(&self.ctx)),
        ];

        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut bytes)?;
        Ok(bytes)
    }

    /// Decode from CBOR
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let value: Value = ciborium::from_reader(bytes)?;

        match value {
            Value::Map(map) => {
                let mut a = None;
                let mut e = None;
                let mut k = None;
                let mut r = None;
                let mut c = None;
                let mut ctx = None;

                for (key, val) in map {
                    match key {
                        Value::Integer(i) if i == 1.into() => a = Some(decode_point(&val)?),
                        Value::Integer(i) if i == 2.into() => e = Some(decode_scalar(&val)?),
                        Value::Integer(i) if i == 3.into() => k = Some(decode_scalar(&val)?),
                        Value::Integer(i) if i == 4.into() => r = Some(decode_scalar(&val)?),
                        Value::Integer(i) if i == 5.into() => c = Some(decode_scalar(&val)?),
                        Value::Integer(i) if i == 6.into() => ctx = Some(decode_scalar(&val)?),
                        _ => {}
                    }
                }

                Ok(CreditToken {
                    a: a.ok_or(CborError::InvalidStructure("missing field 1 (a)"))?,
                    e: e.ok_or(CborError::InvalidStructure("missing field 2 (e)"))?,
                    k: k.ok_or(CborError::InvalidStructure("missing field 3 (k)"))?,
                    r: r.ok_or(CborError::InvalidStructure("missing field 4 (r)"))?,
                    c: c.ok_or(CborError::InvalidStructure("missing field 5 (c)"))?,
                    ctx: ctx.ok_or(CborError::InvalidStructure("missing field 6 (ctx)"))?,
                })
            }
            _ => Err(CborError::InvalidStructure("expected CBOR map")),
        }
    }
}

/// CBOR encoding for PreRefund
impl PreRefund {
    /// Encode to CBOR according to format:
    /// ```text
    /// PreRefund = {
    ///     1: bstr,  ; r (scalar, 32 bytes)
    ///     2: bstr,  ; k (scalar, 32 bytes)
    ///     3: bstr   ; v (scalar, 32 bytes)
    /// }
    /// ```
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let map = vec![
            (Value::Integer(1.into()), encode_scalar(&self.r)),
            (Value::Integer(2.into()), encode_scalar(&self.k)),
            (Value::Integer(3.into()), encode_scalar(&self.v)),
        ];

        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut bytes)?;
        Ok(bytes)
    }

    /// Decode from CBOR
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let value: Value = ciborium::from_reader(bytes)?;

        match value {
            Value::Map(map) => {
                let mut r = None;
                let mut k = None;
                let mut v = None;

                for (key, val) in map {
                    match key {
                        Value::Integer(i) if i == 1.into() => r = Some(decode_scalar(&val)?),
                        Value::Integer(i) if i == 2.into() => k = Some(decode_scalar(&val)?),
                        Value::Integer(i) if i == 3.into() => v = Some(decode_scalar(&val)?),
                        _ => {}
                    }
                }

                Ok(PreRefund {
                    r: r.ok_or(CborError::InvalidStructure("missing field 1 (r)"))?,
                    k: k.ok_or(CborError::InvalidStructure("missing field 2 (k)"))?,
                    v: v.ok_or(CborError::InvalidStructure("missing field 3 (v)"))?,
                })
            }
            _ => Err(CborError::InvalidStructure("expected CBOR map")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use rand_core::OsRng;

    #[test]
    fn test_issuance_request_cbor_roundtrip() {
        let big_k = RistrettoPoint::random(&mut OsRng);
        let mut pok = vec![0; 64];
        OsRng.fill_bytes(&mut pok);

        let request = IssuanceRequest { big_k, pok };

        let bytes = request.to_cbor().unwrap();
        let decoded = IssuanceRequest::from_cbor(&bytes).unwrap();

        assert_eq!(request.big_k, decoded.big_k);
        assert_eq!(request.pok, decoded.pok);
    }

    #[test]
    fn test_issuance_response_cbor_roundtrip() {
        let a = RistrettoPoint::random(&mut OsRng);
        let e = Scalar::random(&mut OsRng);
        let c = Scalar::random(&mut OsRng);
        let mut pok = vec![0; 64];
        OsRng.fill_bytes(&mut pok);

        let response = IssuanceResponse { a, e, c, pok };

        let bytes = response.to_cbor().unwrap();
        let decoded = IssuanceResponse::from_cbor(&bytes).unwrap();

        assert_eq!(response.a, decoded.a);
        assert_eq!(response.e, decoded.e);
        assert_eq!(response.c, decoded.c);
        assert_eq!(response.pok, decoded.pok);
    }

    #[test]
    fn test_refund_cbor_roundtrip() {
        let a = RistrettoPoint::random(&mut OsRng);
        let e = Scalar::random(&mut OsRng);
        let t = Scalar::from(5u64);
        let mut pok = vec![0; 64];
        OsRng.fill_bytes(&mut pok);

        let refund = Refund { a, e, t, pok };

        let bytes = refund.to_cbor().unwrap();
        let decoded = Refund::from_cbor(&bytes).unwrap();

        assert_eq!(refund.a, decoded.a);
        assert_eq!(refund.e, decoded.e);
        assert_eq!(refund.t, decoded.t);
        assert_eq!(refund.pok, decoded.pok);
    }

    #[test]
    fn test_spend_proof_cbor_roundtrip() {
        use group::Group;
        let mut com = [RistrettoPoint::identity(); D];
        let mut t_arr = [RistrettoPoint::identity(); D];
        for j in 0..D {
            com[j] = RistrettoPoint::random(&mut OsRng);
            t_arr[j] = RistrettoPoint::random(&mut OsRng);
        }
        let mut pok = vec![0; 32 * (4 * D + 8)];
        OsRng.fill_bytes(&mut pok);

        let proof = SpendProof {
            k: Scalar::random(&mut OsRng),
            s: Scalar::from(10u64),
            a: Scalar::from(3u64),
            ctx: Scalar::random(&mut OsRng),
            a_prime: RistrettoPoint::random(&mut OsRng),
            b_bar: RistrettoPoint::random(&mut OsRng),
            com,
            t: t_arr,
            pok,
        };

        let bytes = proof.to_cbor().unwrap();
        let decoded = SpendProof::from_cbor(&bytes).unwrap();

        assert_eq!(proof.k, decoded.k);
        assert_eq!(proof.s, decoded.s);
        assert_eq!(proof.a, decoded.a);
        assert_eq!(proof.ctx, decoded.ctx);
        assert_eq!(proof.a_prime, decoded.a_prime);
        assert_eq!(proof.b_bar, decoded.b_bar);
        assert_eq!(proof.com, decoded.com);
        assert_eq!(proof.t, decoded.t);
        assert_eq!(proof.pok, decoded.pok);
    }

    #[test]
    fn test_private_key_cbor_roundtrip() {
        let x = Scalar::random(&mut OsRng);
        let public = PublicKey {
            w: RistrettoPoint::random(&mut OsRng),
        };

        let private_key = PrivateKey { x, public };

        let bytes = private_key.to_cbor().unwrap();
        let decoded = PrivateKey::from_cbor(&bytes).unwrap();

        assert_eq!(private_key.x, decoded.x);
        assert_eq!(private_key.public.w, decoded.public.w);
    }

    #[test]
    fn test_public_key_cbor_roundtrip() {
        let w = RistrettoPoint::random(&mut OsRng);
        let public_key = PublicKey { w };

        let bytes = public_key.to_cbor().unwrap();
        let decoded = PublicKey::from_cbor(&bytes).unwrap();

        assert_eq!(public_key.w, decoded.w);
    }

    #[test]
    fn test_pre_issuance_cbor_roundtrip() {
        let r = Scalar::random(&mut OsRng);
        let k = Scalar::random(&mut OsRng);

        let pre_issuance = PreIssuance { r, k };

        let bytes = pre_issuance.to_cbor().unwrap();
        let decoded = PreIssuance::from_cbor(&bytes).unwrap();

        assert_eq!(pre_issuance.r, decoded.r);
        assert_eq!(pre_issuance.k, decoded.k);
    }

    #[test]
    fn test_credit_token_cbor_roundtrip() {
        let a = RistrettoPoint::random(&mut OsRng);
        let e = Scalar::random(&mut OsRng);
        let k = Scalar::random(&mut OsRng);
        let r = Scalar::random(&mut OsRng);
        let c = Scalar::random(&mut OsRng);
        let ctx = Scalar::random(&mut OsRng);

        let token = CreditToken { a, e, k, r, c, ctx };

        let bytes = token.to_cbor().unwrap();
        let decoded = CreditToken::from_cbor(&bytes).unwrap();

        assert_eq!(token.a, decoded.a);
        assert_eq!(token.e, decoded.e);
        assert_eq!(token.k, decoded.k);
        assert_eq!(token.r, decoded.r);
        assert_eq!(token.c, decoded.c);
        assert_eq!(token.ctx, decoded.ctx);
    }

    #[test]
    fn test_pre_refund_cbor_roundtrip() {
        let r = Scalar::random(&mut OsRng);
        let k = Scalar::random(&mut OsRng);
        let v = Scalar::random(&mut OsRng);

        let pre_refund = PreRefund { r, k, v };

        let bytes = pre_refund.to_cbor().unwrap();
        let decoded = PreRefund::from_cbor(&bytes).unwrap();

        assert_eq!(pre_refund.r, decoded.r);
        assert_eq!(pre_refund.k, decoded.k);
        assert_eq!(pre_refund.v, decoded.v);
    }
}
