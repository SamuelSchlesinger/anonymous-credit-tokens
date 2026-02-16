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

use super::Params;
use bls12_381::{G1Affine, G1Projective, Scalar};

const PROTOCOL_VERSION: &[u8] = b"bls12-381 anonymous-credits-public v1.0";

/// A transcript that accumulates cryptographic protocol messages and generates challenges.
pub(crate) struct Transcript {
    hasher: blake3::Hasher,
}

impl Transcript {
    /// Builds the base BLAKE3 hasher state containing the protocol version
    /// and compressed parameter points.
    pub(crate) fn base_hasher(
        h1: &G1Projective,
        h2: &G1Projective,
        h3: &G1Projective,
        h4: &G1Projective,
    ) -> blake3::Hasher {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&(PROTOCOL_VERSION.len() as u64).to_be_bytes());
        hasher.update(PROTOCOL_VERSION);
        fn add_point(hasher: &mut blake3::Hasher, point: &G1Projective) {
            let compressed = G1Affine::from(point).to_compressed();
            hasher.update(&(compressed.len() as u64).to_be_bytes());
            hasher.update(&compressed);
        }
        add_point(&mut hasher, h1);
        add_point(&mut hasher, h2);
        add_point(&mut hasher, h3);
        add_point(&mut hasher, h4);
        hasher
    }

    /// Creates a new transcript with the given label.
    pub(crate) fn new(params: &Params, label: &[u8]) -> Self {
        let mut transcript = Transcript {
            hasher: params.transcript_base.clone(),
        };
        transcript
            .hasher
            .update(&(label.len() as u64).to_be_bytes());
        transcript.hasher.update(label);
        transcript
    }

    /// Executes a function on a new transcript and returns the resulting challenge.
    pub(crate) fn with(params: &Params, label: &[u8], f: impl FnOnce(&mut Transcript)) -> Scalar {
        let mut transcript = Transcript::new(params, label);
        f(&mut transcript);
        transcript.challenge()
    }

    fn update(&mut self, bytes: &[u8]) {
        self.hasher.update(&(bytes.len() as u64).to_be_bytes());
        self.hasher.update(bytes);
    }

    /// Adds a G1 point to the transcript.
    pub(crate) fn add_element(&mut self, element: &G1Projective) {
        self.update(&G1Affine::from(element).to_compressed());
    }

    /// Adds multiple G1 points to the transcript.
    pub(crate) fn add_elements<'a>(
        &mut self,
        elements: impl Iterator<Item = &'a G1Projective>,
    ) {
        for element in elements {
            self.add_element(element);
        }
    }

    /// Adds a scalar value to the transcript.
    pub(crate) fn add_scalar(&mut self, scalar: &Scalar) {
        self.update(&scalar.to_bytes());
    }

    /// Adds multiple scalar values to the transcript.
    pub(crate) fn add_scalars<'a>(&mut self, scalars: impl Iterator<Item = &'a Scalar>) {
        for scalar in scalars {
            self.add_scalar(scalar);
        }
    }

    /// Generates a challenge scalar from the current transcript state.
    pub(crate) fn challenge(self) -> Scalar {
        let mut reader = self.hasher.finalize_xof();
        let mut output = [0u8; 64];
        reader.fill(&mut output);
        Scalar::from_bytes_wide(&output)
    }
}
