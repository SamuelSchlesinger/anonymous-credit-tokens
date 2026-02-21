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

//! Generic CBOR serialization for Anonymous Credit Token protocol messages.
//!
//! This module implements the CBOR wire format as specified in the
//! [IETF draft](https://datatracker.ietf.org/doc/draft-schlesinger-cfrg-act/).
//! All protocol messages are encoded using deterministic CBOR (RFC 8949) for
//! interoperability.
//!
//! Serialization and deserialization are implemented as inherent methods on
//! each protocol type, parameterized by the [`Ciphersuite`] trait which
//! provides the point/scalar encoding primitives for each concrete
//! ciphersuite (P-256 or Ristretto255).

use crate::ciphersuite::{CborError, Ciphersuite, ErrorCode, ErrorMsg};
use crate::protocol::{
    CreditToken, IssuanceRequest, IssuanceResponse, PreIssuance, PreRefund, PrivateKey, PublicKey,
    Refund, SpendProof,
};
use ciborium::value::Value;
use group::ff::Field;
use group::Group;

/// Maximum CBOR input size for protocol messages (64 KiB).
/// This prevents memory amplification attacks from crafted CBOR payloads.
const MAX_CBOR_INPUT_SIZE: usize = 65536;

/// Parse a CBOR value from bytes with an input size limit.
fn parse_cbor(bytes: &[u8]) -> Result<Value, CborError> {
    if bytes.len() > MAX_CBOR_INPUT_SIZE {
        return Err(CborError::InputTooLarge);
    }
    Ok(ciborium::from_reader(bytes)?)
}

/// Set an Option field, returning an error on duplicate keys.
macro_rules! set_field {
    ($field:expr, $value:expr) => {
        if $field.is_some() {
            return Err(CborError::InvalidStructure("duplicate map key"));
        }
        $field = Some($value);
    };
}

// ── IssuanceRequest ────────────────────────────────────────────────────

impl<C: Ciphersuite> IssuanceRequest<C> {
    /// Encode to CBOR according to spec format:
    /// ```text
    /// IssuanceRequestMsg = {
    ///     1: bstr,  ; K (compressed point)
    ///     2: bstr,  ; gamma (scalar)
    ///     3: bstr,  ; k_bar (scalar)
    ///     4: bstr   ; r_bar (scalar)
    /// }
    /// ```
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let map = vec![
            (Value::Integer(1.into()), C::encode_point_cbor(&self.big_k)),
            (Value::Integer(2.into()), C::encode_scalar_cbor(&self.gamma)),
            (Value::Integer(3.into()), C::encode_scalar_cbor(&self.k_bar)),
            (Value::Integer(4.into()), C::encode_scalar_cbor(&self.r_bar)),
        ];

        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut bytes)?;
        Ok(bytes)
    }

    /// Decode from CBOR
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
                        Value::Integer(i) if i == 1.into() => { set_field!(big_k, C::decode_point_cbor(&v)?); }
                        Value::Integer(i) if i == 2.into() => { set_field!(gamma, C::decode_scalar_cbor(&v)?); }
                        Value::Integer(i) if i == 3.into() => { set_field!(k_bar, C::decode_scalar_cbor(&v)?); }
                        Value::Integer(i) if i == 4.into() => { set_field!(r_bar, C::decode_scalar_cbor(&v)?); }
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

// ── IssuanceResponse ───────────────────────────────────────────────────

impl<C: Ciphersuite> IssuanceResponse<C> {
    /// Encode to CBOR according to spec format:
    /// ```text
    /// IssuanceResponseMsg = {
    ///     1: bstr,  ; A (compressed point)
    ///     2: bstr,  ; e (scalar)
    ///     3: bstr,  ; gamma_resp (scalar)
    ///     4: bstr,  ; z (scalar)
    ///     5: bstr,  ; c (scalar)
    ///     6: bstr   ; ctx (scalar)
    /// }
    /// ```
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let map = vec![
            (Value::Integer(1.into()), C::encode_point_cbor(&self.a)),
            (Value::Integer(2.into()), C::encode_scalar_cbor(&self.e)),
            (Value::Integer(3.into()), C::encode_scalar_cbor(&self.gamma)),
            (Value::Integer(4.into()), C::encode_scalar_cbor(&self.z)),
            (Value::Integer(5.into()), C::encode_scalar_cbor(&self.c)),
            (Value::Integer(6.into()), C::encode_scalar_cbor(&self.ctx)),
        ];

        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut bytes)?;
        Ok(bytes)
    }

    /// Decode from CBOR
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let value = parse_cbor(bytes)?;

        match value {
            Value::Map(map) => {
                let mut a = None;
                let mut e = None;
                let mut gamma = None;
                let mut z = None;
                let mut c = None;
                let mut ctx = None;

                for (k, v) in map {
                    match k {
                        Value::Integer(i) if i == 1.into() => { set_field!(a, C::decode_point_cbor(&v)?); }
                        Value::Integer(i) if i == 2.into() => { set_field!(e, C::decode_scalar_cbor(&v)?); }
                        Value::Integer(i) if i == 3.into() => { set_field!(gamma, C::decode_scalar_cbor(&v)?); }
                        Value::Integer(i) if i == 4.into() => { set_field!(z, C::decode_scalar_cbor(&v)?); }
                        Value::Integer(i) if i == 5.into() => { set_field!(c, C::decode_scalar_cbor(&v)?); }
                        Value::Integer(i) if i == 6.into() => { set_field!(ctx, C::decode_scalar_cbor(&v)?); }
                        _ => { return Err(CborError::InvalidStructure("unexpected map key")); }
                    }
                }

                Ok(IssuanceResponse {
                    a: a.ok_or(CborError::InvalidStructure("missing field 1 (A)"))?,
                    e: e.ok_or(CborError::InvalidStructure("missing field 2 (e)"))?,
                    gamma: gamma.ok_or(CborError::InvalidStructure("missing field 3 (gamma)"))?,
                    z: z.ok_or(CborError::InvalidStructure("missing field 4 (z)"))?,
                    c: c.ok_or(CborError::InvalidStructure("missing field 5 (c)"))?,
                    ctx: ctx.ok_or(CborError::InvalidStructure("missing field 6 (ctx)"))?,
                })
            }
            _ => Err(CborError::InvalidStructure("expected CBOR map")),
        }
    }
}

// ── SpendProof ─────────────────────────────────────────────────────────

impl<C: Ciphersuite, const L: usize> SpendProof<C, L> {
    /// Encode to CBOR according to spec format:
    /// ```text
    /// SpendProofMsg = {
    ///     1: bstr,              ; k (nullifier)
    ///     2: bstr,              ; s (spend amount)
    ///     3: bstr,              ; A' (compressed point)
    ///     4: bstr,              ; B_bar (compressed point)
    ///     5: [* bstr],          ; Com array (L compressed points)
    ///     6: bstr,              ; gamma (scalar)
    ///     7: bstr,              ; e_bar (scalar)
    ///     8: bstr,              ; r2_bar (scalar)
    ///     9: bstr,              ; r3_bar (scalar)
    ///     10: bstr,             ; c_bar (scalar)
    ///     11: bstr,             ; r_bar (scalar)
    ///     12: bstr,             ; w00 (scalar)
    ///     13: bstr,             ; w01 (scalar)
    ///     14: [* bstr],         ; gamma0 array (L scalars)
    ///     15: [* [bstr, bstr]], ; z array (L pairs of scalars)
    ///     16: bstr,             ; k_bar (scalar)
    ///     17: bstr,             ; s_bar (scalar)
    ///     18: bstr              ; ctx (request_context scalar)
    /// }
    /// ```
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        // Com array
        let com_array: Vec<Value> = self.com.iter().map(|p| C::encode_point_cbor(p)).collect();

        // gamma0 array
        let gamma0_array: Vec<Value> = self
            .gamma0
            .iter()
            .map(|s| C::encode_scalar_cbor(s))
            .collect();

        // z array (pairs)
        let z_array: Vec<Value> = self
            .z
            .iter()
            .map(|pair| {
                Value::Array(vec![
                    C::encode_scalar_cbor(&pair[0]),
                    C::encode_scalar_cbor(&pair[1]),
                ])
            })
            .collect();

        let map = vec![
            (Value::Integer(1.into()), C::encode_scalar_cbor(&self.k)),
            (Value::Integer(2.into()), C::encode_scalar_cbor(&self.s)),
            (Value::Integer(3.into()), C::encode_point_cbor(&self.a_prime)),
            (Value::Integer(4.into()), C::encode_point_cbor(&self.b_bar)),
            (Value::Integer(5.into()), Value::Array(com_array)),
            (Value::Integer(6.into()), C::encode_scalar_cbor(&self.gamma)),
            (Value::Integer(7.into()), C::encode_scalar_cbor(&self.e_bar)),
            (Value::Integer(8.into()), C::encode_scalar_cbor(&self.r2_bar)),
            (Value::Integer(9.into()), C::encode_scalar_cbor(&self.r3_bar)),
            (Value::Integer(10.into()), C::encode_scalar_cbor(&self.c_bar)),
            (Value::Integer(11.into()), C::encode_scalar_cbor(&self.r_bar)),
            (Value::Integer(12.into()), C::encode_scalar_cbor(&self.w00)),
            (Value::Integer(13.into()), C::encode_scalar_cbor(&self.w01)),
            (Value::Integer(14.into()), Value::Array(gamma0_array)),
            (Value::Integer(15.into()), Value::Array(z_array)),
            (Value::Integer(16.into()), C::encode_scalar_cbor(&self.k_bar)),
            (Value::Integer(17.into()), C::encode_scalar_cbor(&self.s_bar)),
            (Value::Integer(18.into()), C::encode_scalar_cbor(&self.ctx)),
        ];

        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut bytes)?;
        Ok(bytes)
    }

    /// Decode from CBOR
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let value = parse_cbor(bytes)?;

        match value {
            Value::Map(map) => {
                let mut k = None;
                let mut ctx = None;
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
                        Value::Integer(i) if i == 1.into() => { set_field!(k, C::decode_scalar_cbor(&val)?); }
                        Value::Integer(i) if i == 2.into() => { set_field!(s, C::decode_scalar_cbor(&val)?); }
                        Value::Integer(i) if i == 3.into() => { set_field!(a_prime, C::decode_point_cbor(&val)?); }
                        Value::Integer(i) if i == 4.into() => { set_field!(b_bar, C::decode_point_cbor(&val)?); }
                        Value::Integer(i) if i == 5.into() => {
                            if com.is_some() {
                                return Err(CborError::InvalidStructure("duplicate map key"));
                            }
                            if let Value::Array(arr) = val {
                                let com_arr: Result<Vec<_>, _> =
                                    arr.iter().map(|v| C::decode_point_cbor(v)).collect();
                                let com_arr = com_arr?;
                                if com_arr.len() == L {
                                    let mut com_fixed = [C::Point::identity(); L];
                                    com_fixed.copy_from_slice(&com_arr);
                                    com = Some(com_fixed);
                                } else {
                                    return Err(CborError::InvalidStructure(
                                        "Com array wrong size",
                                    ));
                                }
                            } else {
                                return Err(CborError::InvalidStructure("expected array for Com"));
                            }
                        }
                        Value::Integer(i) if i == 6.into() => { set_field!(gamma, C::decode_scalar_cbor(&val)?); }
                        Value::Integer(i) if i == 7.into() => { set_field!(e_bar, C::decode_scalar_cbor(&val)?); }
                        Value::Integer(i) if i == 8.into() => { set_field!(r2_bar, C::decode_scalar_cbor(&val)?); }
                        Value::Integer(i) if i == 9.into() => { set_field!(r3_bar, C::decode_scalar_cbor(&val)?); }
                        Value::Integer(i) if i == 10.into() => { set_field!(c_bar, C::decode_scalar_cbor(&val)?); }
                        Value::Integer(i) if i == 11.into() => { set_field!(r_bar, C::decode_scalar_cbor(&val)?); }
                        Value::Integer(i) if i == 12.into() => { set_field!(w00, C::decode_scalar_cbor(&val)?); }
                        Value::Integer(i) if i == 13.into() => { set_field!(w01, C::decode_scalar_cbor(&val)?); }
                        Value::Integer(i) if i == 14.into() => {
                            if gamma0.is_some() {
                                return Err(CborError::InvalidStructure("duplicate map key"));
                            }
                            if let Value::Array(arr) = val {
                                let gamma0_arr: Result<Vec<_>, _> =
                                    arr.iter().map(|v| C::decode_scalar_cbor(v)).collect();
                                let gamma0_arr = gamma0_arr?;
                                if gamma0_arr.len() == L {
                                    let mut gamma0_fixed = [<C::Scalar as Field>::ZERO; L];
                                    gamma0_fixed.copy_from_slice(&gamma0_arr);
                                    gamma0 = Some(gamma0_fixed);
                                } else {
                                    return Err(CborError::InvalidStructure(
                                        "gamma0 array wrong size",
                                    ));
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
                                    .iter()
                                    .map(|v| {
                                        if let Value::Array(pair) = v {
                                            if pair.len() == 2 {
                                                Ok([
                                                    C::decode_scalar_cbor(&pair[0])?,
                                                    C::decode_scalar_cbor(&pair[1])?,
                                                ])
                                            } else {
                                                Err(CborError::InvalidStructure(
                                                    "z pair wrong size",
                                                ))
                                            }
                                        } else {
                                            Err(CborError::InvalidStructure(
                                                "expected array for z pair",
                                            ))
                                        }
                                    })
                                    .collect();
                                let z_arr = z_arr?;
                                if z_arr.len() == L {
                                    let mut z_fixed =
                                        [[<C::Scalar as Field>::ZERO; 2]; L];
                                    z_fixed.copy_from_slice(&z_arr);
                                    z = Some(z_fixed);
                                } else {
                                    return Err(CborError::InvalidStructure("z array wrong size"));
                                }
                            } else {
                                return Err(CborError::InvalidStructure("expected array for z"));
                            }
                        }
                        Value::Integer(i) if i == 16.into() => { set_field!(k_bar, C::decode_scalar_cbor(&val)?); }
                        Value::Integer(i) if i == 17.into() => { set_field!(s_bar, C::decode_scalar_cbor(&val)?); }
                        Value::Integer(i) if i == 18.into() => { set_field!(ctx, C::decode_scalar_cbor(&val)?); }
                        _ => { return Err(CborError::InvalidStructure("unexpected map key")); }
                    }
                }

                Ok(SpendProof {
                    k: k.ok_or(CborError::InvalidStructure("missing field 1"))?,
                    ctx: ctx.ok_or(CborError::InvalidStructure("missing field 18"))?,
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

// ── Refund ─────────────────────────────────────────────────────────────

impl<C: Ciphersuite> Refund<C> {
    /// Encode to CBOR according to spec format:
    /// ```text
    /// RefundMsg = {
    ///     1: bstr,  ; A* (compressed point)
    ///     2: bstr,  ; e* (scalar)
    ///     3: bstr,  ; gamma (scalar)
    ///     4: bstr,  ; z (scalar)
    ///     5: bstr   ; t (scalar)
    /// }
    /// ```
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let map = vec![
            (Value::Integer(1.into()), C::encode_point_cbor(&self.a)),
            (Value::Integer(2.into()), C::encode_scalar_cbor(&self.e)),
            (Value::Integer(3.into()), C::encode_scalar_cbor(&self.gamma)),
            (Value::Integer(4.into()), C::encode_scalar_cbor(&self.z)),
            (Value::Integer(5.into()), C::encode_scalar_cbor(&self.t)),
        ];

        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut bytes)?;
        Ok(bytes)
    }

    /// Decode from CBOR
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let value = parse_cbor(bytes)?;

        match value {
            Value::Map(map) => {
                let mut a = None;
                let mut e = None;
                let mut gamma = None;
                let mut z = None;
                let mut t = None;

                for (k, v) in map {
                    match k {
                        Value::Integer(i) if i == 1.into() => { set_field!(a, C::decode_point_cbor(&v)?); }
                        Value::Integer(i) if i == 2.into() => { set_field!(e, C::decode_scalar_cbor(&v)?); }
                        Value::Integer(i) if i == 3.into() => { set_field!(gamma, C::decode_scalar_cbor(&v)?); }
                        Value::Integer(i) if i == 4.into() => { set_field!(z, C::decode_scalar_cbor(&v)?); }
                        Value::Integer(i) if i == 5.into() => { set_field!(t, C::decode_scalar_cbor(&v)?); }
                        _ => { return Err(CborError::InvalidStructure("unexpected map key")); }
                    }
                }

                Ok(Refund {
                    a: a.ok_or(CborError::InvalidStructure("missing field 1 (A*)"))?,
                    e: e.ok_or(CborError::InvalidStructure("missing field 2 (e*)"))?,
                    gamma: gamma.ok_or(CborError::InvalidStructure("missing field 3 (gamma)"))?,
                    z: z.ok_or(CborError::InvalidStructure("missing field 4 (z)"))?,
                    t: t.ok_or(CborError::InvalidStructure("missing field 5 (t)"))?,
                })
            }
            _ => Err(CborError::InvalidStructure("expected CBOR map")),
        }
    }
}

// ── PrivateKey ─────────────────────────────────────────────────────────

impl<C: Ciphersuite> PrivateKey<C> {
    /// Encode to CBOR according to format:
    /// ```text
    /// PrivateKey = {
    ///     1: bstr,  ; x (scalar)
    ///     2: bstr   ; w (public key point)
    /// }
    /// ```
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let map = vec![
            (Value::Integer(1.into()), C::encode_scalar_cbor(&self.x)),
            (Value::Integer(2.into()), C::encode_point_cbor(&self.public.w)),
        ];

        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut bytes)?;
        Ok(bytes)
    }

    /// Decode from CBOR
    ///
    /// Validates that the public key `w` matches the secret scalar `x`
    /// (i.e. `w == g * x`) to prevent use of inconsistent key material.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let value = parse_cbor(bytes)?;

        match value {
            Value::Map(map) => {
                let mut x = None;
                let mut w = None;

                for (k, v) in map {
                    match k {
                        Value::Integer(i) if i == 1.into() => { set_field!(x, C::decode_scalar_cbor(&v)?); }
                        Value::Integer(i) if i == 2.into() => { set_field!(w, C::decode_point_cbor(&v)?); }
                        _ => { return Err(CborError::InvalidStructure("unexpected map key")); }
                    }
                }

                let x = x.ok_or(CborError::InvalidStructure("missing field 1 (x)"))?;
                let w = w.ok_or(CborError::InvalidStructure("missing field 2 (w)"))?;

                // Validate w == g^x to prevent use of inconsistent key material
                let expected_w = C::generator_mul(&x);
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

// ── PublicKey ───────────────────────────────────────────────────────────

impl<C: Ciphersuite> PublicKey<C> {
    /// Encode to CBOR according to format:
    /// ```text
    /// PublicKey = bstr  ; w (compressed point)
    /// ```
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let mut bytes = Vec::new();
        ciborium::into_writer(&C::encode_point_cbor(&self.w), &mut bytes)?;
        Ok(bytes)
    }

    /// Decode from CBOR
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let value = parse_cbor(bytes)?;
        let w = C::decode_point_cbor(&value)?;
        Ok(PublicKey { w })
    }
}

// ── PreIssuance ────────────────────────────────────────────────────────

impl<C: Ciphersuite> PreIssuance<C> {
    /// Encode to CBOR according to format:
    /// ```text
    /// PreIssuance = {
    ///     1: bstr,  ; r (scalar)
    ///     2: bstr   ; k (scalar)
    /// }
    /// ```
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let map = vec![
            (Value::Integer(1.into()), C::encode_scalar_cbor(&self.r)),
            (Value::Integer(2.into()), C::encode_scalar_cbor(&self.k)),
        ];

        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut bytes)?;
        Ok(bytes)
    }

    /// Decode from CBOR
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CborError> {
        let value = parse_cbor(bytes)?;

        match value {
            Value::Map(map) => {
                let mut r = None;
                let mut k = None;

                for (key, val) in map {
                    match key {
                        Value::Integer(i) if i == 1.into() => { set_field!(r, C::decode_scalar_cbor(&val)?); }
                        Value::Integer(i) if i == 2.into() => { set_field!(k, C::decode_scalar_cbor(&val)?); }
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

// ── CreditToken ────────────────────────────────────────────────────────

impl<C: Ciphersuite> CreditToken<C> {
    /// Encode to CBOR according to format:
    /// ```text
    /// CreditToken = {
    ///     1: bstr,  ; a (compressed point)
    ///     2: bstr,  ; e (scalar)
    ///     3: bstr,  ; k (scalar)
    ///     4: bstr,  ; r (scalar)
    ///     5: bstr,  ; c (scalar)
    ///     6: bstr   ; ctx (scalar)
    /// }
    /// ```
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let map = vec![
            (Value::Integer(1.into()), C::encode_point_cbor(&self.a)),
            (Value::Integer(2.into()), C::encode_scalar_cbor(&self.e)),
            (Value::Integer(3.into()), C::encode_scalar_cbor(&self.k)),
            (Value::Integer(4.into()), C::encode_scalar_cbor(&self.r)),
            (Value::Integer(5.into()), C::encode_scalar_cbor(&self.c)),
            (Value::Integer(6.into()), C::encode_scalar_cbor(&self.ctx)),
        ];

        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut bytes)?;
        Ok(bytes)
    }

    /// Decode from CBOR
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
                        Value::Integer(i) if i == 1.into() => { set_field!(a, C::decode_point_cbor(&val)?); }
                        Value::Integer(i) if i == 2.into() => { set_field!(e, C::decode_scalar_cbor(&val)?); }
                        Value::Integer(i) if i == 3.into() => { set_field!(k, C::decode_scalar_cbor(&val)?); }
                        Value::Integer(i) if i == 4.into() => { set_field!(r, C::decode_scalar_cbor(&val)?); }
                        Value::Integer(i) if i == 5.into() => { set_field!(c, C::decode_scalar_cbor(&val)?); }
                        Value::Integer(i) if i == 6.into() => { set_field!(ctx, C::decode_scalar_cbor(&val)?); }
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

// ── PreRefund ──────────────────────────────────────────────────────────

impl<C: Ciphersuite> PreRefund<C> {
    /// Encode to CBOR according to format:
    /// ```text
    /// PreRefund = {
    ///     1: bstr,  ; r (scalar)
    ///     2: bstr,  ; k (scalar)
    ///     3: bstr,  ; m (scalar)
    ///     4: bstr   ; ctx (scalar)
    /// }
    /// ```
    pub fn to_cbor(&self) -> Result<Vec<u8>, CborError> {
        let map = vec![
            (Value::Integer(1.into()), C::encode_scalar_cbor(&self.r)),
            (Value::Integer(2.into()), C::encode_scalar_cbor(&self.k)),
            (Value::Integer(3.into()), C::encode_scalar_cbor(&self.m)),
            (Value::Integer(4.into()), C::encode_scalar_cbor(&self.ctx)),
        ];

        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut bytes)?;
        Ok(bytes)
    }

    /// Decode from CBOR
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
                        Value::Integer(i) if i == 1.into() => { set_field!(r, C::decode_scalar_cbor(&val)?); }
                        Value::Integer(i) if i == 2.into() => { set_field!(k, C::decode_scalar_cbor(&val)?); }
                        Value::Integer(i) if i == 3.into() => { set_field!(m, C::decode_scalar_cbor(&val)?); }
                        Value::Integer(i) if i == 4.into() => { set_field!(ctx, C::decode_scalar_cbor(&val)?); }
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

// ── ErrorMsg ───────────────────────────────────────────────────────────

impl ErrorMsg {
    /// Encode to CBOR according to spec format:
    /// ```text
    /// ErrorMsg = {
    ///     1: uint,   ; error_code
    ///     2: tstr    ; error_message (for debugging only)
    /// }
    /// ```
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

    /// Decode from CBOR
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
                                return Err(CborError::InvalidStructure(
                                    "expected integer for error_code",
                                ));
                            }
                        }
                        Value::Integer(i) if i == 2.into() => {
                            if error_message.is_some() {
                                return Err(CborError::InvalidStructure("duplicate map key"));
                            }
                            if let Value::Text(msg) = v {
                                error_message = Some(msg);
                            } else {
                                return Err(CborError::InvalidStructure(
                                    "expected text for error_message",
                                ));
                            }
                        }
                        _ => {
                            return Err(CborError::InvalidStructure("unexpected map key"));
                        }
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
