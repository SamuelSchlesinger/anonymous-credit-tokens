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

//! CBOR serialization for Anonymous Credit Token protocol messages (BLS12-381).
//!
//! All protocol messages are encoded using deterministic CBOR (RFC 8949).

use crate::{
    CreditToken, ErrorCode, ErrorMsg, IssuanceRequest, IssuanceResponse, PreIssuance, PreRefund,
    PrivateKey, PublicKey, Refund, SpendProof,
};
use bls12_381::{G1Affine, G1Projective, G2Affine, Scalar};
use ciborium::value::Value;
use ff::PrimeField;

/// Maximum CBOR input size for protocol messages (64 KiB).
const MAX_CBOR_INPUT_SIZE: usize = 65536;

/// Error type for CBOR serialization/deserialization
#[derive(Debug)]
pub enum CborError {
    /// Error from ciborium library
    Ciborium(ciborium::de::Error<std::io::Error>),
    /// Invalid CBOR structure
    InvalidStructure(&'static str),
    /// Invalid field value
    InvalidValue(&'static str),
    /// Input exceeds maximum size
    InputTooLarge,
}

impl std::fmt::Display for CborError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CborError::Ciborium(e) => write!(f, "CBOR error: {e}"),
            CborError::InvalidStructure(msg) => write!(f, "invalid CBOR structure: {msg}"),
            CborError::InvalidValue(msg) => write!(f, "invalid CBOR value: {msg}"),
            CborError::InputTooLarge => write!(f, "CBOR input exceeds maximum size"),
        }
    }
}

impl std::error::Error for CborError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CborError::Ciborium(e) => Some(e),
            CborError::InvalidStructure(_) | CborError::InvalidValue(_) | CborError::InputTooLarge => None,
        }
    }
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

fn parse_cbor(bytes: &[u8]) -> Result<Value, CborError> {
    if bytes.len() > MAX_CBOR_INPUT_SIZE {
        return Err(CborError::InputTooLarge);
    }
    Ok(ciborium::from_reader(bytes)?)
}

macro_rules! set_field {
    ($field:expr, $value:expr) => {
        if $field.is_some() {
            return Err(CborError::InvalidStructure("duplicate map key"));
        }
        $field = Some($value);
    };
}

/// Encode a G1 point as a 48-byte compressed CBOR byte string
fn encode_g1_point(point: &G1Projective) -> Value {
    Value::Bytes(G1Affine::from(point).to_compressed().to_vec())
}

/// Encode a G2 point as a 96-byte compressed CBOR byte string
fn encode_g2_point(point: &G2Affine) -> Value {
    Value::Bytes(point.to_compressed().to_vec())
}

/// Encode a Scalar as a 32-byte CBOR byte string (little-endian, BLS12-381 native)
fn encode_scalar(scalar: &Scalar) -> Value {
    Value::Bytes(scalar.to_bytes().to_vec())
}

/// Decode a G1 point from a CBOR byte string (48-byte compressed)
fn decode_g1_point(value: &Value) -> Result<G1Projective, CborError> {
    match value {
        Value::Bytes(bytes) if bytes.len() == 48 => {
            let mut arr = [0u8; 48];
            arr.copy_from_slice(bytes);
            let affine: Option<G1Affine> = G1Affine::from_compressed(&arr).into();
            affine
                .map(G1Projective::from)
                .ok_or(CborError::InvalidValue("invalid G1 point"))
        }
        _ => Err(CborError::InvalidStructure(
            "expected 48-byte array for G1 point",
        )),
    }
}

/// Decode a G2 point from a CBOR byte string (96-byte compressed)
fn decode_g2_point(value: &Value) -> Result<G2Affine, CborError> {
    match value {
        Value::Bytes(bytes) if bytes.len() == 96 => {
            let mut arr = [0u8; 96];
            arr.copy_from_slice(bytes);
            let affine: Option<G2Affine> = G2Affine::from_compressed(&arr).into();
            affine.ok_or(CborError::InvalidValue("invalid G2 point"))
        }
        _ => Err(CborError::InvalidStructure(
            "expected 96-byte array for G2 point",
        )),
    }
}

/// Decode a Scalar from a CBOR byte string (32-byte little-endian, canonical)
fn decode_scalar(value: &Value) -> Result<Scalar, CborError> {
    match value {
        Value::Bytes(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            let scalar: Option<Scalar> = Scalar::from_repr(arr).into();
            scalar.ok_or(CborError::InvalidValue("non-canonical scalar encoding"))
        }
        _ => Err(CborError::InvalidStructure(
            "expected 32-byte array for scalar",
        )),
    }
}

impl IssuanceRequest {
    /// Encode to CBOR.
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let map = vec![
            (Value::Integer(1.into()), encode_g1_point(&self.big_k)),
            (Value::Integer(2.into()), encode_scalar(&self.gamma)),
            (Value::Integer(3.into()), encode_scalar(&self.k_bar)),
            (Value::Integer(4.into()), encode_scalar(&self.r_bar)),
        ];
        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut bytes)?;
        Ok(bytes)
    }

    /// Decode from CBOR.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let value = parse_cbor(bytes)?;
        match value {
            Value::Map(map) => {
                let mut big_k = None;
                let mut gamma = None;
                let mut k_bar = None;
                let mut r_bar = None;
                for (k, v) in map {
                    match k {
                        Value::Integer(i) if i == 1.into() => { set_field!(big_k, decode_g1_point(&v)?); }
                        Value::Integer(i) if i == 2.into() => { set_field!(gamma, decode_scalar(&v)?); }
                        Value::Integer(i) if i == 3.into() => { set_field!(k_bar, decode_scalar(&v)?); }
                        Value::Integer(i) if i == 4.into() => { set_field!(r_bar, decode_scalar(&v)?); }
                        _ => { return Err(CborError::InvalidStructure("unexpected map key")); }
                    }
                }
                Ok(IssuanceRequest {
                    big_k: big_k.ok_or(CborError::InvalidStructure("missing field 1 (K)"))?,
                    gamma: gamma.ok_or(CborError::InvalidStructure("missing field 2 (gamma)"))?,
                    k_bar: k_bar.ok_or(CborError::InvalidStructure("missing field 3 (k_bar)"))?,
                    r_bar: r_bar.ok_or(CborError::InvalidStructure("missing field 4 (r_bar)"))?,
                })
            }
            _ => Err(CborError::InvalidStructure("expected CBOR map")),
        }
    }
}

impl IssuanceResponse {
    /// Encode to CBOR (no DLEQ fields: just A, e, c, ctx).
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let map = vec![
            (Value::Integer(1.into()), encode_g1_point(&self.a)),
            (Value::Integer(2.into()), encode_scalar(&self.e)),
            (Value::Integer(3.into()), encode_scalar(&self.c)),
            (Value::Integer(4.into()), encode_scalar(&self.ctx)),
        ];
        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut bytes)?;
        Ok(bytes)
    }

    /// Decode from CBOR.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let value = parse_cbor(bytes)?;
        match value {
            Value::Map(map) => {
                let mut a = None;
                let mut e = None;
                let mut c = None;
                let mut ctx = None;
                for (k, v) in map {
                    match k {
                        Value::Integer(i) if i == 1.into() => { set_field!(a, decode_g1_point(&v)?); }
                        Value::Integer(i) if i == 2.into() => { set_field!(e, decode_scalar(&v)?); }
                        Value::Integer(i) if i == 3.into() => { set_field!(c, decode_scalar(&v)?); }
                        Value::Integer(i) if i == 4.into() => { set_field!(ctx, decode_scalar(&v)?); }
                        _ => { return Err(CborError::InvalidStructure("unexpected map key")); }
                    }
                }
                Ok(IssuanceResponse {
                    a: a.ok_or(CborError::InvalidStructure("missing field 1 (A)"))?,
                    e: e.ok_or(CborError::InvalidStructure("missing field 2 (e)"))?,
                    c: c.ok_or(CborError::InvalidStructure("missing field 3 (c)"))?,
                    ctx: ctx.ok_or(CborError::InvalidStructure("missing field 4 (ctx)"))?,
                })
            }
            _ => Err(CborError::InvalidStructure("expected CBOR map")),
        }
    }
}

impl<const L: usize> SpendProof<L> {
    /// Encode to CBOR (includes a_bar field for public verification).
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let com_array: Vec<Value> = self.com.iter().map(encode_g1_point).collect();
        let gamma0_array: Vec<Value> = self.gamma0.iter().map(encode_scalar).collect();
        let z_array: Vec<Value> = self
            .z
            .iter()
            .map(|pair| Value::Array(vec![encode_scalar(&pair[0]), encode_scalar(&pair[1])]))
            .collect();

        let map = vec![
            (Value::Integer(1.into()), encode_scalar(&self.k)),
            (Value::Integer(2.into()), encode_scalar(&self.s)),
            (Value::Integer(3.into()), encode_g1_point(&self.a_prime)),
            (Value::Integer(4.into()), encode_g1_point(&self.b_bar)),
            (Value::Integer(5.into()), Value::Array(com_array)),
            (Value::Integer(6.into()), encode_scalar(&self.gamma)),
            (Value::Integer(7.into()), encode_scalar(&self.e_bar)),
            (Value::Integer(8.into()), encode_scalar(&self.r2_bar)),
            (Value::Integer(9.into()), encode_scalar(&self.r3_bar)),
            (Value::Integer(10.into()), encode_scalar(&self.c_bar)),
            (Value::Integer(11.into()), encode_scalar(&self.r_bar)),
            (Value::Integer(12.into()), encode_scalar(&self.w00)),
            (Value::Integer(13.into()), encode_scalar(&self.w01)),
            (Value::Integer(14.into()), Value::Array(gamma0_array)),
            (Value::Integer(15.into()), Value::Array(z_array)),
            (Value::Integer(16.into()), encode_scalar(&self.k_bar)),
            (Value::Integer(17.into()), encode_scalar(&self.s_bar)),
            (Value::Integer(18.into()), encode_scalar(&self.ctx)),
            (Value::Integer(19.into()), encode_g1_point(&self.a_bar)),
        ];

        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut bytes)?;
        Ok(bytes)
    }

    /// Decode from CBOR.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let value = parse_cbor(bytes)?;
        match value {
            Value::Map(map) => {
                let mut k = None;
                let mut ctx = None;
                let mut s = None;
                let mut a_prime = None;
                let mut b_bar = None;
                let mut a_bar = None;
                let mut com = None;
                let mut gamma = None;
                let mut e_bar = None;
                let mut r2_bar = None;
                let mut r3_bar = None;
                let mut c_bar = None;
                let mut r_bar = None;
                let mut w00 = None;
                let mut w01 = None;
                let mut gamma0 = None;
                let mut z = None;
                let mut k_bar = None;
                let mut s_bar = None;

                for (key, val) in map {
                    match key {
                        Value::Integer(i) if i == 1.into() => { set_field!(k, decode_scalar(&val)?); }
                        Value::Integer(i) if i == 2.into() => { set_field!(s, decode_scalar(&val)?); }
                        Value::Integer(i) if i == 3.into() => { set_field!(a_prime, decode_g1_point(&val)?); }
                        Value::Integer(i) if i == 4.into() => { set_field!(b_bar, decode_g1_point(&val)?); }
                        Value::Integer(i) if i == 5.into() => {
                            if com.is_some() {
                                return Err(CborError::InvalidStructure("duplicate map key"));
                            }
                            if let Value::Array(arr) = val {
                                let com_arr: Result<Vec<_>, _> =
                                    arr.into_iter().map(|v| decode_g1_point(&v)).collect();
                                let com_arr = com_arr?;
                                if com_arr.len() == L {
                                    let mut com_fixed = [G1Projective::identity(); L];
                                    com_fixed.copy_from_slice(&com_arr);
                                    com = Some(com_fixed);
                                } else {
                                    return Err(CborError::InvalidStructure("Com array wrong size"));
                                }
                            } else {
                                return Err(CborError::InvalidStructure("expected array for Com"));
                            }
                        }
                        Value::Integer(i) if i == 6.into() => { set_field!(gamma, decode_scalar(&val)?); }
                        Value::Integer(i) if i == 7.into() => { set_field!(e_bar, decode_scalar(&val)?); }
                        Value::Integer(i) if i == 8.into() => { set_field!(r2_bar, decode_scalar(&val)?); }
                        Value::Integer(i) if i == 9.into() => { set_field!(r3_bar, decode_scalar(&val)?); }
                        Value::Integer(i) if i == 10.into() => { set_field!(c_bar, decode_scalar(&val)?); }
                        Value::Integer(i) if i == 11.into() => { set_field!(r_bar, decode_scalar(&val)?); }
                        Value::Integer(i) if i == 12.into() => { set_field!(w00, decode_scalar(&val)?); }
                        Value::Integer(i) if i == 13.into() => { set_field!(w01, decode_scalar(&val)?); }
                        Value::Integer(i) if i == 14.into() => {
                            if gamma0.is_some() {
                                return Err(CborError::InvalidStructure("duplicate map key"));
                            }
                            if let Value::Array(arr) = val {
                                let gamma0_arr: Result<Vec<_>, _> =
                                    arr.into_iter().map(|v| decode_scalar(&v)).collect();
                                let gamma0_arr = gamma0_arr?;
                                if gamma0_arr.len() == L {
                                    let mut gamma0_fixed = [Scalar::zero(); L];
                                    gamma0_fixed.copy_from_slice(&gamma0_arr);
                                    gamma0 = Some(gamma0_fixed);
                                } else {
                                    return Err(CborError::InvalidStructure("gamma0 array wrong size"));
                                }
                            } else {
                                return Err(CborError::InvalidStructure("expected array for gamma0"));
                            }
                        }
                        Value::Integer(i) if i == 15.into() => {
                            if z.is_some() {
                                return Err(CborError::InvalidStructure("duplicate map key"));
                            }
                            if let Value::Array(arr) = val {
                                let z_arr: Result<Vec<_>, _> = arr
                                    .into_iter()
                                    .map(|v| {
                                        if let Value::Array(pair) = v {
                                            if pair.len() == 2 {
                                                Ok([
                                                    decode_scalar(&pair[0])?,
                                                    decode_scalar(&pair[1])?,
                                                ])
                                            } else {
                                                Err(CborError::InvalidStructure("z pair wrong size"))
                                            }
                                        } else {
                                            Err(CborError::InvalidStructure("expected array for z pair"))
                                        }
                                    })
                                    .collect();
                                let z_arr = z_arr?;
                                if z_arr.len() == L {
                                    let mut z_fixed = [[Scalar::zero(); 2]; L];
                                    z_fixed.copy_from_slice(&z_arr);
                                    z = Some(z_fixed);
                                } else {
                                    return Err(CborError::InvalidStructure("z array wrong size"));
                                }
                            } else {
                                return Err(CborError::InvalidStructure("expected array for z"));
                            }
                        }
                        Value::Integer(i) if i == 16.into() => { set_field!(k_bar, decode_scalar(&val)?); }
                        Value::Integer(i) if i == 17.into() => { set_field!(s_bar, decode_scalar(&val)?); }
                        Value::Integer(i) if i == 18.into() => { set_field!(ctx, decode_scalar(&val)?); }
                        Value::Integer(i) if i == 19.into() => { set_field!(a_bar, decode_g1_point(&val)?); }
                        _ => { return Err(CborError::InvalidStructure("unexpected map key")); }
                    }
                }

                Ok(SpendProof {
                    k: k.ok_or(CborError::InvalidStructure("missing field 1"))?,
                    ctx: ctx.ok_or(CborError::InvalidStructure("missing field 18"))?,
                    s: s.ok_or(CborError::InvalidStructure("missing field 2"))?,
                    a_prime: a_prime.ok_or(CborError::InvalidStructure("missing field 3"))?,
                    b_bar: b_bar.ok_or(CborError::InvalidStructure("missing field 4"))?,
                    a_bar: a_bar.ok_or(CborError::InvalidStructure("missing field 19"))?,
                    com: com.ok_or(CborError::InvalidStructure("missing field 5"))?,
                    gamma: gamma.ok_or(CborError::InvalidStructure("missing field 6"))?,
                    e_bar: e_bar.ok_or(CborError::InvalidStructure("missing field 7"))?,
                    r2_bar: r2_bar.ok_or(CborError::InvalidStructure("missing field 8"))?,
                    r3_bar: r3_bar.ok_or(CborError::InvalidStructure("missing field 9"))?,
                    c_bar: c_bar.ok_or(CborError::InvalidStructure("missing field 10"))?,
                    r_bar: r_bar.ok_or(CborError::InvalidStructure("missing field 11"))?,
                    w00: w00.ok_or(CborError::InvalidStructure("missing field 12"))?,
                    w01: w01.ok_or(CborError::InvalidStructure("missing field 13"))?,
                    gamma0: gamma0.ok_or(CborError::InvalidStructure("missing field 14"))?,
                    z: z.ok_or(CborError::InvalidStructure("missing field 15"))?,
                    k_bar: k_bar.ok_or(CborError::InvalidStructure("missing field 16"))?,
                    s_bar: s_bar.ok_or(CborError::InvalidStructure("missing field 17"))?,
                })
            }
            _ => Err(CborError::InvalidStructure("expected CBOR map")),
        }
    }
}

impl Refund {
    /// Encode to CBOR (no DLEQ fields: just A, e, t).
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let map = vec![
            (Value::Integer(1.into()), encode_g1_point(&self.a)),
            (Value::Integer(2.into()), encode_scalar(&self.e)),
            (Value::Integer(3.into()), encode_scalar(&self.t)),
        ];
        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut bytes)?;
        Ok(bytes)
    }

    /// Decode from CBOR.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let value = parse_cbor(bytes)?;
        match value {
            Value::Map(map) => {
                let mut a = None;
                let mut e = None;
                let mut t = None;
                for (k, v) in map {
                    match k {
                        Value::Integer(i) if i == 1.into() => { set_field!(a, decode_g1_point(&v)?); }
                        Value::Integer(i) if i == 2.into() => { set_field!(e, decode_scalar(&v)?); }
                        Value::Integer(i) if i == 3.into() => { set_field!(t, decode_scalar(&v)?); }
                        _ => { return Err(CborError::InvalidStructure("unexpected map key")); }
                    }
                }
                Ok(Refund {
                    a: a.ok_or(CborError::InvalidStructure("missing field 1 (A*)"))?,
                    e: e.ok_or(CborError::InvalidStructure("missing field 2 (e*)"))?,
                    t: t.ok_or(CborError::InvalidStructure("missing field 3 (t)"))?,
                })
            }
            _ => Err(CborError::InvalidStructure("expected CBOR map")),
        }
    }
}

impl PrivateKey {
    /// Encode to CBOR.
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let map = vec![
            (Value::Integer(1.into()), encode_scalar(&self.x)),
            (Value::Integer(2.into()), encode_g2_point(&self.public.w)),
        ];
        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut bytes)?;
        Ok(bytes)
    }

    /// Decode from CBOR.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let value = parse_cbor(bytes)?;
        match value {
            Value::Map(map) => {
                let mut x = None;
                let mut w = None;
                for (k, v) in map {
                    match k {
                        Value::Integer(i) if i == 1.into() => { set_field!(x, decode_scalar(&v)?); }
                        Value::Integer(i) if i == 2.into() => { set_field!(w, decode_g2_point(&v)?); }
                        _ => { return Err(CborError::InvalidStructure("unexpected map key")); }
                    }
                }
                let x = x.ok_or(CborError::InvalidStructure("missing field 1 (x)"))?;
                let w = w.ok_or(CborError::InvalidStructure("missing field 2 (w)"))?;

                let expected_w = G2Affine::from(G2Affine::generator() * x);
                if w != expected_w {
                    return Err(CborError::InvalidValue(
                        "public key w does not match secret scalar x",
                    ));
                }
                Ok(PrivateKey {
                    x,
                    public: PublicKey { w },
                })
            }
            _ => Err(CborError::InvalidStructure("expected CBOR map")),
        }
    }
}

impl PublicKey {
    /// Encode to CBOR.
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let mut bytes = Vec::new();
        ciborium::into_writer(&encode_g2_point(&self.w), &mut bytes)?;
        Ok(bytes)
    }

    /// Decode from CBOR.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let value = parse_cbor(bytes)?;
        let w = decode_g2_point(&value)?;
        Ok(PublicKey { w })
    }
}

impl PreIssuance {
    /// Encode to CBOR.
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let map = vec![
            (Value::Integer(1.into()), encode_scalar(&self.r)),
            (Value::Integer(2.into()), encode_scalar(&self.k)),
        ];
        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut bytes)?;
        Ok(bytes)
    }

    /// Decode from CBOR.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let value = parse_cbor(bytes)?;
        match value {
            Value::Map(map) => {
                let mut r = None;
                let mut k = None;
                for (key, val) in map {
                    match key {
                        Value::Integer(i) if i == 1.into() => { set_field!(r, decode_scalar(&val)?); }
                        Value::Integer(i) if i == 2.into() => { set_field!(k, decode_scalar(&val)?); }
                        _ => { return Err(CborError::InvalidStructure("unexpected map key")); }
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

impl CreditToken {
    /// Encode to CBOR.
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let map = vec![
            (Value::Integer(1.into()), encode_g1_point(&self.a)),
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

    /// Decode from CBOR.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let value = parse_cbor(bytes)?;
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
                        Value::Integer(i) if i == 1.into() => { set_field!(a, decode_g1_point(&val)?); }
                        Value::Integer(i) if i == 2.into() => { set_field!(e, decode_scalar(&val)?); }
                        Value::Integer(i) if i == 3.into() => { set_field!(k, decode_scalar(&val)?); }
                        Value::Integer(i) if i == 4.into() => { set_field!(r, decode_scalar(&val)?); }
                        Value::Integer(i) if i == 5.into() => { set_field!(c, decode_scalar(&val)?); }
                        Value::Integer(i) if i == 6.into() => { set_field!(ctx, decode_scalar(&val)?); }
                        _ => { return Err(CborError::InvalidStructure("unexpected map key")); }
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

impl PreRefund {
    /// Encode to CBOR.
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let map = vec![
            (Value::Integer(1.into()), encode_scalar(&self.r)),
            (Value::Integer(2.into()), encode_scalar(&self.k)),
            (Value::Integer(3.into()), encode_scalar(&self.m)),
            (Value::Integer(4.into()), encode_scalar(&self.ctx)),
        ];
        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut bytes)?;
        Ok(bytes)
    }

    /// Decode from CBOR.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let value = parse_cbor(bytes)?;
        match value {
            Value::Map(map) => {
                let mut r = None;
                let mut k = None;
                let mut m = None;
                let mut ctx = None;
                for (key, val) in map {
                    match key {
                        Value::Integer(i) if i == 1.into() => { set_field!(r, decode_scalar(&val)?); }
                        Value::Integer(i) if i == 2.into() => { set_field!(k, decode_scalar(&val)?); }
                        Value::Integer(i) if i == 3.into() => { set_field!(m, decode_scalar(&val)?); }
                        Value::Integer(i) if i == 4.into() => { set_field!(ctx, decode_scalar(&val)?); }
                        _ => { return Err(CborError::InvalidStructure("unexpected map key")); }
                    }
                }
                Ok(PreRefund {
                    r: r.ok_or(CborError::InvalidStructure("missing field 1 (r)"))?,
                    k: k.ok_or(CborError::InvalidStructure("missing field 2 (k)"))?,
                    m: m.ok_or(CborError::InvalidStructure("missing field 3 (m)"))?,
                    ctx: ctx.ok_or(CborError::InvalidStructure("missing field 4 (ctx)"))?,
                })
            }
            _ => Err(CborError::InvalidStructure("expected CBOR map")),
        }
    }
}

impl ErrorMsg {
    /// Encode to CBOR.
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let map = vec![
            (
                Value::Integer(1.into()),
                Value::Integer((self.error_code as u32).into()),
            ),
            (
                Value::Integer(2.into()),
                Value::Text(self.error_message.clone()),
            ),
        ];
        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut bytes)?;
        Ok(bytes)
    }

    /// Decode from CBOR.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let value = parse_cbor(bytes)?;
        match value {
            Value::Map(map) => {
                let mut error_code = None;
                let mut error_message = None;
                for (k, v) in map {
                    match k {
                        Value::Integer(i) if i == 1.into() => {
                            if error_code.is_some() {
                                return Err(CborError::InvalidStructure("duplicate map key"));
                            }
                            if let Value::Integer(code) = v {
                                let code: i128 = code.into();
                                let code = u32::try_from(code).map_err(|_| {
                                    CborError::InvalidValue("error_code out of range")
                                })?;
                                error_code = Some(
                                    ErrorCode::from_u32(code)
                                        .ok_or(CborError::InvalidValue("unknown error_code"))?,
                                );
                            } else {
                                return Err(CborError::InvalidStructure("expected integer for error_code"));
                            }
                        }
                        Value::Integer(i) if i == 2.into() => {
                            if error_message.is_some() {
                                return Err(CborError::InvalidStructure("duplicate map key"));
                            }
                            if let Value::Text(msg) = v {
                                error_message = Some(msg);
                            } else {
                                return Err(CborError::InvalidStructure("expected text for error_message"));
                            }
                        }
                        _ => { return Err(CborError::InvalidStructure("unexpected map key")); }
                    }
                }
                Ok(ErrorMsg {
                    error_code: error_code
                        .ok_or(CborError::InvalidStructure("missing field 1 (error_code)"))?,
                    error_message: error_message.ok_or(CborError::InvalidStructure(
                        "missing field 2 (error_message)",
                    ))?,
                })
            }
            _ => Err(CborError::InvalidStructure("expected CBOR map")),
        }
    }
}
