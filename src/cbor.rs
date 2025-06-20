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

use crate::{IssuanceRequest, IssuanceResponse, SpendProof, Refund, L, PrivateKey, PublicKey, PreIssuance, CreditToken, PreRefund};
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
        _ => Err(CborError::InvalidStructure("expected 32-byte array for point")),
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
        _ => Err(CborError::InvalidStructure("expected 32-byte array for scalar")),
    }
}

/// CBOR encoding for IssuanceRequest
impl IssuanceRequest {
    /// Encode to CBOR according to spec format:
    /// ```text
    /// IssuanceRequestMsg = {
    ///     1: bstr,  ; K (compressed Ristretto point, 32 bytes)
    ///     2: bstr,  ; gamma (scalar, 32 bytes)
    ///     3: bstr,  ; k_bar (scalar, 32 bytes)
    ///     4: bstr   ; r_bar (scalar, 32 bytes)
    /// }
    /// ```
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let map = vec![
            (Value::Integer(1.into()), encode_point(&self.big_k)),
            (Value::Integer(2.into()), encode_scalar(&self.gamma)),
            (Value::Integer(3.into()), encode_scalar(&self.k_bar)),
            (Value::Integer(4.into()), encode_scalar(&self.r_bar)),
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
                let mut gamma = None;
                let mut k_bar = None;
                let mut r_bar = None;
                
                for (k, v) in map {
                    match k {
                        Value::Integer(i) if i == 1.into() => big_k = Some(decode_point(&v)?),
                        Value::Integer(i) if i == 2.into() => gamma = Some(decode_scalar(&v)?),
                        Value::Integer(i) if i == 3.into() => k_bar = Some(decode_scalar(&v)?),
                        Value::Integer(i) if i == 4.into() => r_bar = Some(decode_scalar(&v)?),
                        _ => {}
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

/// CBOR encoding for IssuanceResponse
impl IssuanceResponse {
    /// Encode to CBOR according to spec format:
    /// ```text
    /// IssuanceResponseMsg = {
    ///     1: bstr,  ; A (compressed Ristretto point, 32 bytes)
    ///     2: bstr,  ; e (scalar, 32 bytes)
    ///     3: bstr,  ; gamma_resp (scalar, 32 bytes)
    ///     4: bstr,  ; z (scalar, 32 bytes)
    ///     5: bstr   ; c (scalar, 32 bytes)
    /// }
    /// ```
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let map = vec![
            (Value::Integer(1.into()), encode_point(&self.a)),
            (Value::Integer(2.into()), encode_scalar(&self.e)),
            (Value::Integer(3.into()), encode_scalar(&self.gamma)),
            (Value::Integer(4.into()), encode_scalar(&self.z)),
            (Value::Integer(5.into()), encode_scalar(&self.c)),
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
                let mut gamma = None;
                let mut z = None;
                let mut c = None;
                
                for (k, v) in map {
                    match k {
                        Value::Integer(i) if i == 1.into() => a = Some(decode_point(&v)?),
                        Value::Integer(i) if i == 2.into() => e = Some(decode_scalar(&v)?),
                        Value::Integer(i) if i == 3.into() => gamma = Some(decode_scalar(&v)?),
                        Value::Integer(i) if i == 4.into() => z = Some(decode_scalar(&v)?),
                        Value::Integer(i) if i == 5.into() => c = Some(decode_scalar(&v)?),
                        _ => {}
                    }
                }
                
                Ok(IssuanceResponse {
                    a: a.ok_or(CborError::InvalidStructure("missing field 1 (A)"))?,
                    e: e.ok_or(CborError::InvalidStructure("missing field 2 (e)"))?,
                    gamma: gamma.ok_or(CborError::InvalidStructure("missing field 3 (gamma)"))?,
                    z: z.ok_or(CborError::InvalidStructure("missing field 4 (z)"))?,
                    c: c.ok_or(CborError::InvalidStructure("missing field 5 (c)"))?,
                })
            }
            _ => Err(CborError::InvalidStructure("expected CBOR map")),
        }
    }
}

/// CBOR encoding for SpendProof
impl SpendProof {
    /// Encode to CBOR according to spec format:
    /// ```text
    /// SpendProofMsg = {
    ///     1: bstr,           ; k (nullifier, 32 bytes)
    ///     2: bstr,           ; s (spend amount, 32 bytes)
    ///     3: bstr,           ; A' (compressed point, 32 bytes)
    ///     4: bstr,           ; B_bar (compressed point, 32 bytes)
    ///     5: [* bstr],       ; Com array (L compressed points)
    ///     6: bstr,           ; gamma (scalar, 32 bytes)
    ///     7: bstr,           ; e_bar (scalar, 32 bytes)
    ///     8: bstr,           ; r2_bar (scalar, 32 bytes)
    ///     9: bstr,           ; r3_bar (scalar, 32 bytes)
    ///     10: bstr,          ; c_bar (scalar, 32 bytes)
    ///     11: bstr,          ; r_bar (scalar, 32 bytes)
    ///     12: bstr,          ; w00 (scalar, 32 bytes)
    ///     13: bstr,          ; w01 (scalar, 32 bytes)
    ///     14: [* bstr],      ; gamma0 array (L scalars)
    ///     15: [* [bstr, bstr]], ; z array (L pairs of scalars)
    ///     16: bstr,          ; k_bar (scalar, 32 bytes)
    ///     17: bstr           ; s_bar (scalar, 32 bytes)
    /// }
    /// ```
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        // Com array
        let com_array: Vec<Value> = self.com.iter().map(encode_point).collect();
        
        // gamma0 array
        let gamma0_array: Vec<Value> = self.gamma0.iter().map(encode_scalar).collect();
        
        // z array (pairs)
        let z_array: Vec<Value> = self.z.iter().map(|pair| {
            Value::Array(vec![encode_scalar(&pair[0]), encode_scalar(&pair[1])])
        }).collect();
        
        let map = vec![
            (Value::Integer(1.into()), encode_scalar(&self.k)),
            (Value::Integer(2.into()), encode_scalar(&self.s)),
            (Value::Integer(3.into()), encode_point(&self.a_prime)),
            (Value::Integer(4.into()), encode_point(&self.b_bar)),
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
                let mut a_prime = None;
                let mut b_bar = None;
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
                        Value::Integer(i) if i == 1.into() => k = Some(decode_scalar(&val)?),
                        Value::Integer(i) if i == 2.into() => s = Some(decode_scalar(&val)?),
                        Value::Integer(i) if i == 3.into() => a_prime = Some(decode_point(&val)?),
                        Value::Integer(i) if i == 4.into() => b_bar = Some(decode_point(&val)?),
                        Value::Integer(i) if i == 5.into() => {
                            if let Value::Array(arr) = val {
                                let com_arr: Result<Vec<_>, _> = arr.into_iter()
                                    .map(|v| decode_point(&v))
                                    .collect();
                                let com_arr = com_arr?;
                                if com_arr.len() == L {
                                    use group::Group;
                                    let mut com_fixed = [RistrettoPoint::identity(); L];
                                    com_fixed.copy_from_slice(&com_arr);
                                    com = Some(com_fixed);
                                } else {
                                    return Err(CborError::InvalidStructure("Com array wrong size"));
                                }
                            }
                        }
                        Value::Integer(i) if i == 6.into() => gamma = Some(decode_scalar(&val)?),
                        Value::Integer(i) if i == 7.into() => e_bar = Some(decode_scalar(&val)?),
                        Value::Integer(i) if i == 8.into() => r2_bar = Some(decode_scalar(&val)?),
                        Value::Integer(i) if i == 9.into() => r3_bar = Some(decode_scalar(&val)?),
                        Value::Integer(i) if i == 10.into() => c_bar = Some(decode_scalar(&val)?),
                        Value::Integer(i) if i == 11.into() => r_bar = Some(decode_scalar(&val)?),
                        Value::Integer(i) if i == 12.into() => w00 = Some(decode_scalar(&val)?),
                        Value::Integer(i) if i == 13.into() => w01 = Some(decode_scalar(&val)?),
                        Value::Integer(i) if i == 14.into() => {
                            if let Value::Array(arr) = val {
                                let gamma0_arr: Result<Vec<_>, _> = arr.into_iter()
                                    .map(|v| decode_scalar(&v))
                                    .collect();
                                let gamma0_arr = gamma0_arr?;
                                if gamma0_arr.len() == L {
                                    let mut gamma0_fixed = [Scalar::ZERO; L];
                                    gamma0_fixed.copy_from_slice(&gamma0_arr);
                                    gamma0 = Some(gamma0_fixed);
                                } else {
                                    return Err(CborError::InvalidStructure("gamma0 array wrong size"));
                                }
                            }
                        }
                        Value::Integer(i) if i == 15.into() => {
                            if let Value::Array(arr) = val {
                                let z_arr: Result<Vec<_>, _> = arr.into_iter()
                                    .map(|v| {
                                        if let Value::Array(pair) = v {
                                            if pair.len() == 2 {
                                                Ok([decode_scalar(&pair[0])?, decode_scalar(&pair[1])?])
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
                                    let mut z_fixed = [[Scalar::ZERO; 2]; L];
                                    z_fixed.copy_from_slice(&z_arr);
                                    z = Some(z_fixed);
                                } else {
                                    return Err(CborError::InvalidStructure("z array wrong size"));
                                }
                            }
                        }
                        Value::Integer(i) if i == 16.into() => k_bar = Some(decode_scalar(&val)?),
                        Value::Integer(i) if i == 17.into() => s_bar = Some(decode_scalar(&val)?),
                        _ => {}
                    }
                }
                
                Ok(SpendProof {
                    k: k.ok_or(CborError::InvalidStructure("missing field 1"))?,
                    s: s.ok_or(CborError::InvalidStructure("missing field 2"))?,
                    a_prime: a_prime.ok_or(CborError::InvalidStructure("missing field 3"))?,
                    b_bar: b_bar.ok_or(CborError::InvalidStructure("missing field 4"))?,
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

/// CBOR encoding for Refund
impl Refund {
    /// Encode to CBOR according to spec format:
    /// ```text
    /// RefundMsg = {
    ///     1: bstr,  ; A* (compressed Ristretto point, 32 bytes)
    ///     2: bstr,  ; e* (scalar, 32 bytes)
    ///     3: bstr,  ; gamma (scalar, 32 bytes)
    ///     4: bstr   ; z (scalar, 32 bytes)
    /// }
    /// ```
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let map = vec![
            (Value::Integer(1.into()), encode_point(&self.a)),
            (Value::Integer(2.into()), encode_scalar(&self.e)),
            (Value::Integer(3.into()), encode_scalar(&self.gamma)),
            (Value::Integer(4.into()), encode_scalar(&self.z)),
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
                let mut gamma = None;
                let mut z = None;
                
                for (k, v) in map {
                    match k {
                        Value::Integer(i) if i == 1.into() => a = Some(decode_point(&v)?),
                        Value::Integer(i) if i == 2.into() => e = Some(decode_scalar(&v)?),
                        Value::Integer(i) if i == 3.into() => gamma = Some(decode_scalar(&v)?),
                        Value::Integer(i) if i == 4.into() => z = Some(decode_scalar(&v)?),
                        _ => {}
                    }
                }
                
                Ok(Refund {
                    a: a.ok_or(CborError::InvalidStructure("missing field 1 (A*)"))?,
                    e: e.ok_or(CborError::InvalidStructure("missing field 2 (e*)"))?,
                    gamma: gamma.ok_or(CborError::InvalidStructure("missing field 3 (gamma)"))?,
                    z: z.ok_or(CborError::InvalidStructure("missing field 4 (z)"))?,
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
    ///     5: bstr   ; c (scalar, 32 bytes)
    /// }
    /// ```
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let map = vec![
            (Value::Integer(1.into()), encode_point(&self.a)),
            (Value::Integer(2.into()), encode_scalar(&self.e)),
            (Value::Integer(3.into()), encode_scalar(&self.k)),
            (Value::Integer(4.into()), encode_scalar(&self.r)),
            (Value::Integer(5.into()), encode_scalar(&self.c)),
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
                
                for (key, val) in map {
                    match key {
                        Value::Integer(i) if i == 1.into() => a = Some(decode_point(&val)?),
                        Value::Integer(i) if i == 2.into() => e = Some(decode_scalar(&val)?),
                        Value::Integer(i) if i == 3.into() => k = Some(decode_scalar(&val)?),
                        Value::Integer(i) if i == 4.into() => r = Some(decode_scalar(&val)?),
                        Value::Integer(i) if i == 5.into() => c = Some(decode_scalar(&val)?),
                        _ => {}
                    }
                }
                
                Ok(CreditToken {
                    a: a.ok_or(CborError::InvalidStructure("missing field 1 (a)"))?,
                    e: e.ok_or(CborError::InvalidStructure("missing field 2 (e)"))?,
                    k: k.ok_or(CborError::InvalidStructure("missing field 3 (k)"))?,
                    r: r.ok_or(CborError::InvalidStructure("missing field 4 (r)"))?,
                    c: c.ok_or(CborError::InvalidStructure("missing field 5 (c)"))?,
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
    ///     3: bstr   ; m (scalar, 32 bytes)
    /// }
    /// ```
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let map = vec![
            (Value::Integer(1.into()), encode_scalar(&self.r)),
            (Value::Integer(2.into()), encode_scalar(&self.k)),
            (Value::Integer(3.into()), encode_scalar(&self.m)),
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
                let mut m = None;
                
                for (key, val) in map {
                    match key {
                        Value::Integer(i) if i == 1.into() => r = Some(decode_scalar(&val)?),
                        Value::Integer(i) if i == 2.into() => k = Some(decode_scalar(&val)?),
                        Value::Integer(i) if i == 3.into() => m = Some(decode_scalar(&val)?),
                        _ => {}
                    }
                }
                
                Ok(PreRefund {
                    r: r.ok_or(CborError::InvalidStructure("missing field 1 (r)"))?,
                    k: k.ok_or(CborError::InvalidStructure("missing field 2 (k)"))?,
                    m: m.ok_or(CborError::InvalidStructure("missing field 3 (m)"))?,
                })
            }
            _ => Err(CborError::InvalidStructure("expected CBOR map")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    
    #[test]
    fn test_issuance_request_cbor_roundtrip() {
        let big_k = RistrettoPoint::random(&mut OsRng);
        let gamma = Scalar::random(&mut OsRng);
        let k_bar = Scalar::random(&mut OsRng);
        let r_bar = Scalar::random(&mut OsRng);
        
        let request = IssuanceRequest {
            big_k,
            gamma,
            k_bar,
            r_bar,
        };
        
        let bytes = request.to_cbor().unwrap();
        let decoded = IssuanceRequest::from_cbor(&bytes).unwrap();
        
        assert_eq!(request.big_k, decoded.big_k);
        assert_eq!(request.gamma, decoded.gamma);
        assert_eq!(request.k_bar, decoded.k_bar);
        assert_eq!(request.r_bar, decoded.r_bar);
    }
    
    #[test]
    fn test_issuance_response_cbor_roundtrip() {
        let a = RistrettoPoint::random(&mut OsRng);
        let e = Scalar::random(&mut OsRng);
        let gamma = Scalar::random(&mut OsRng);
        let z = Scalar::random(&mut OsRng);
        let c = Scalar::random(&mut OsRng);
        
        let response = IssuanceResponse {
            a,
            e,
            gamma,
            z,
            c,
        };
        
        let bytes = response.to_cbor().unwrap();
        let decoded = IssuanceResponse::from_cbor(&bytes).unwrap();
        
        assert_eq!(response.a, decoded.a);
        assert_eq!(response.e, decoded.e);
        assert_eq!(response.gamma, decoded.gamma);
        assert_eq!(response.z, decoded.z);
        assert_eq!(response.c, decoded.c);
    }
    
    #[test]
    fn test_refund_cbor_roundtrip() {
        let a = RistrettoPoint::random(&mut OsRng);
        let e = Scalar::random(&mut OsRng);
        let gamma = Scalar::random(&mut OsRng);
        let z = Scalar::random(&mut OsRng);
        
        let refund = Refund {
            a,
            e,
            gamma,
            z,
        };
        
        let bytes = refund.to_cbor().unwrap();
        let decoded = Refund::from_cbor(&bytes).unwrap();
        
        assert_eq!(refund.a, decoded.a);
        assert_eq!(refund.e, decoded.e);
        assert_eq!(refund.gamma, decoded.gamma);
        assert_eq!(refund.z, decoded.z);
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
        
        let token = CreditToken { a, e, k, r, c };
        
        let bytes = token.to_cbor().unwrap();
        let decoded = CreditToken::from_cbor(&bytes).unwrap();
        
        assert_eq!(token.a, decoded.a);
        assert_eq!(token.e, decoded.e);
        assert_eq!(token.k, decoded.k);
        assert_eq!(token.r, decoded.r);
        assert_eq!(token.c, decoded.c);
    }
    
    #[test]
    fn test_pre_refund_cbor_roundtrip() {
        let r = Scalar::random(&mut OsRng);
        let k = Scalar::random(&mut OsRng);
        let m = Scalar::random(&mut OsRng);
        
        let pre_refund = PreRefund { r, k, m };
        
        let bytes = pre_refund.to_cbor().unwrap();
        let decoded = PreRefund::from_cbor(&bytes).unwrap();
        
        assert_eq!(pre_refund.r, decoded.r);
        assert_eq!(pre_refund.k, decoded.k);
        assert_eq!(pre_refund.m, decoded.m);
    }
}