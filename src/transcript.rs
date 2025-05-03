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
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const PROTOCOL_LABEL: &[u8] = b"curve25519-ristretto anonymous-credentials v0.1.1";

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
        let mut t = Transcript {
            hasher: blake3::Hasher::new(),
        };
        t.update(PROTOCOL_LABEL);
        t.update(
            &bincode::serde::encode_to_vec(params.h1.basepoint(), bincode::config::standard())
                .unwrap(),
        );
        t.update(
            &bincode::serde::encode_to_vec(params.h2.basepoint(), bincode::config::standard())
                .unwrap(),
        );
        t.update(
            &bincode::serde::encode_to_vec(params.h3.basepoint(), bincode::config::standard())
                .unwrap(),
        );
        t.update(label);
        t
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
        self.hasher.update(&bytes.len().to_be_bytes());
        self.hasher.update(bytes);
    }

    /// Adds a Ristretto point to the transcript.
    ///
    /// # Arguments
    ///
    /// * `element` - A reference to a `RistrettoPoint` to add to the transcript
    pub(crate) fn add_element(&mut self, element: &RistrettoPoint) {
        self.update(&bincode::serde::encode_to_vec(element, bincode::config::standard()).unwrap());
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
        self.update(&bincode::serde::encode_to_vec(scalar, bincode::config::standard()).unwrap());
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

    /// Creates a deterministic random number generator from the transcript state.
    ///
    /// # Returns
    ///
    /// A `ChaCha20Rng` seeded with the current transcript state
    pub(crate) fn rng(self) -> ChaCha20Rng {
        ChaCha20Rng::from_seed(*self.hasher.finalize().as_bytes())
    }

    /// Generates a challenge scalar from the current transcript state.
    ///
    /// This method creates a deterministic RNG from the transcript and uses it
    /// to generate a random scalar value.
    ///
    /// # Returns
    ///
    /// A `Scalar` representing the challenge derived from the transcript
    pub(crate) fn challenge(self) -> Scalar {
        Scalar::random(&mut self.rng())
    }
}
