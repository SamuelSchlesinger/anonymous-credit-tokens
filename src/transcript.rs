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

//! A transcript system for Fiat-Shamir transformations.
//!
//! This module implements a simple transcript system that can be used to securely
//! generate challenge values for zero-knowledge proofs. It uses the BLAKE3 hash
//! function to accumulate transcript state and derive challenge values.
//!
//! The transcript system is used throughout the anonymous credit scheme to
//! make interactive zero-knowledge protocols non-interactive by deriving
//! challenge values deterministically from the protocol messages.

use super::Params;
use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::Scalar;

const PROTOCOL_VERSION: &[u8] = b"curve25519-ristretto anonymous-credits v1.0";

/// A transcript that accumulates cryptographic protocol messages and generates challenges.
///
/// The `Transcript` is used to implement the Fiat-Shamir transform, which converts
/// interactive zero-knowledge protocols into non-interactive ones by deriving challenge
/// values from the transcript of the protocol so far.
pub(crate) struct Transcript {
    /// The underlying BLAKE3 hasher for accumulating transcript state
    hasher: blake3::Hasher,
}

impl Transcript {
    /// Creates a new transcript with the given label.
    ///
    /// The label helps to domain-separate different transcript uses, ensuring
    /// that challenges generated for one protocol cannot be reused for another.
    ///
    /// # Arguments
    ///
    /// * `label` - A byte slice used to identify this transcript's purpose
    ///
    /// # Returns
    ///
    /// A new `Transcript` instance initialized with the label
    pub(crate) fn new(params: &Params, label: &[u8]) -> Self {
        let mut transcript = Transcript {
            hasher: blake3::Hasher::new(),
        };
        // Add protocol version with length prefix
        transcript.hasher.update(&(PROTOCOL_VERSION.len() as u64).to_be_bytes());
        transcript.hasher.update(PROTOCOL_VERSION);
        // Add the parameters' base points using Encode() which includes length prefixes
        transcript.add_element(&params.h1.basepoint());
        transcript.add_element(&params.h2.basepoint());
        transcript.add_element(&params.h3.basepoint());
        // Add label with length prefix
        transcript.hasher.update(&(label.len() as u64).to_be_bytes());
        transcript.hasher.update(label);
        
        transcript
    }

    /// Executes a function on a new transcript and returns the resulting challenge.
    ///
    /// This is a convenience method for creating a transcript, adding elements to it,
    /// and then generating a challenge value, all in a single call.
    ///
    /// # Arguments
    ///
    /// * `label` - A byte slice used to identify this transcript's purpose
    /// * `f` - A function that adds elements to the transcript
    ///
    /// # Returns
    ///
    /// A `Scalar` representing the challenge derived from the transcript
    pub(crate) fn with(params: &Params, label: &[u8], f: impl FnOnce(&mut Transcript)) -> Scalar {
        let mut transcript = Transcript::new(params, label);
        f(&mut transcript);
        transcript.challenge()
    }

    fn update(&mut self, bytes: &[u8]) {
        self.hasher.update(&(bytes.len() as u64).to_be_bytes());
        self.hasher.update(bytes);
    }

    /// Adds a Ristretto point to the transcript.
    ///
    /// # Arguments
    ///
    /// * `element` - A reference to a `RistrettoPoint` to add to the transcript
    pub(crate) fn add_element(&mut self, element: &RistrettoPoint) {
        self.update(&element.compress().as_bytes()[..]);
    }

    /// Adds multiple Ristretto points to the transcript.
    ///
    /// # Arguments
    ///
    /// * `elements` - An iterator over references to `RistrettoPoint`s to add to the transcript
    pub(crate) fn add_elements<'a>(&mut self, elements: impl Iterator<Item = &'a RistrettoPoint>) {
        for element in elements {
            self.add_element(element);
        }
    }

    /// Adds a scalar value to the transcript.
    ///
    /// # Arguments
    ///
    /// * `scalar` - A reference to a `Scalar` to add to the transcript
    pub(crate) fn add_scalar(&mut self, scalar: &Scalar) {
        // Scalars are 32 bytes in little-endian format
        self.update(scalar.as_bytes());
    }

    /// Adds multiple Ristretto points to the transcript.
    ///
    /// # Arguments
    ///
    /// * `scalars` - An iterator over references to `RistrettoPoint`s to add to the transcript
    pub(crate) fn add_scalars<'a>(&mut self, scalars: impl Iterator<Item = &'a Scalar>) {
        for scalar in scalars {
            self.add_scalar(scalar);
        }
    }

    /// Generates a challenge scalar from the current transcript state.
    ///
    /// This method finalizes the hash and uses `Scalar::from_hash` with 64 bytes
    /// for better uniformity.
    ///
    /// # Returns
    ///
    /// A `Scalar` representing the challenge derived from the transcript
    pub(crate) fn challenge(self) -> Scalar {
        let mut reader = self.hasher.finalize_xof();
        let mut output = [0u8; 64];
        reader.fill(&mut output);
        Scalar::from_bytes_mod_order_wide(&output)
    }
}
