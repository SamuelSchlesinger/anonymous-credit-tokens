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

#![deny(missing_docs)]
#![forbid(unsafe_code)]

//! Anonymous Credit Tokens — dual ciphersuite crate.
//!
//! Enable the `p256` or `ristretto255` feature to use the corresponding ciphersuite.

pub(crate) mod ciphersuite;
pub(crate) mod transcript;
pub(crate) mod protocol;
mod cbor;

#[cfg(test)]
pub(crate) mod tests_common;

#[cfg(feature = "p256")]
pub mod p256;

#[cfg(feature = "ristretto255")]
pub mod ristretto255;

#[cfg(feature = "secp256k1")]
pub mod secp256k1;

#[cfg(feature = "p384")]
pub mod p384;
