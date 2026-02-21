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

//! Generic transcript system for Fiat-Shamir transformations.
//!
//! This module implements a simple transcript system that can be used to securely
//! generate challenge values for zero-knowledge proofs. It uses the BLAKE3 hash
//! function to accumulate transcript state and derive challenge values.

use crate::ciphersuite::Ciphersuite;
use std::marker::PhantomData;

/// A transcript that accumulates cryptographic protocol messages and generates challenges.
///
/// The `Transcript` is used to implement the Fiat-Shamir transform, which converts
/// interactive zero-knowledge protocols into non-interactive ones by deriving challenge
/// values from the transcript of the protocol so far.
pub(crate) struct Transcript<C: Ciphersuite> {
    hasher: blake3::Hasher,
    _marker: PhantomData<C>,
}

impl<C: Ciphersuite> Transcript<C> {
    /// Builds the base BLAKE3 hasher state containing the protocol version
    /// and compressed parameter points.
    ///
    /// Implements spec Section 3.6 (CreateTranscript) steps 1-6. The
    /// resulting hasher is cached in `Params::transcript_base` and cloned
    /// (cheaply) by every subsequent `Transcript::new` call, which only
    /// needs to append step 7 (the label). This avoids 4 expensive point
    /// compressions per transcript without changing the hash output.
    pub(crate) fn base_hasher(
        h1: &C::ParamPoint,
        h2: &C::ParamPoint,
        h3: &C::ParamPoint,
        h4: &C::ParamPoint,
    ) -> blake3::Hasher {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&(C::PROTOCOL_VERSION.len() as u64).to_be_bytes());
        hasher.update(C::PROTOCOL_VERSION);

        let encode = |pp: &C::ParamPoint, h: &mut blake3::Hasher| {
            let point = C::param_to_point(pp);
            let bytes = C::encode_point_for_transcript(&point);
            let bytes = bytes.as_ref();
            h.update(&(bytes.len() as u64).to_be_bytes());
            h.update(bytes);
        };
        encode(h1, &mut hasher);
        encode(h2, &mut hasher);
        encode(h3, &mut hasher);
        encode(h4, &mut hasher);

        hasher
    }

    /// Creates a new transcript with the given label.
    ///
    /// Clones the cached base hasher state (which already contains the protocol
    /// version and compressed parameter points) and appends the label.
    pub(crate) fn new(transcript_base: &blake3::Hasher, label: &[u8]) -> Self {
        let mut transcript = Transcript {
            hasher: transcript_base.clone(),
            _marker: PhantomData,
        };
        transcript
            .hasher
            .update(&(label.len() as u64).to_be_bytes());
        transcript.hasher.update(label);
        transcript
    }

    /// Executes a function on a new transcript and returns the resulting challenge.
    pub(crate) fn with(
        transcript_base: &blake3::Hasher,
        label: &[u8],
        f: impl FnOnce(&mut Transcript<C>),
    ) -> C::Scalar {
        let mut transcript = Transcript::<C>::new(transcript_base, label);
        f(&mut transcript);
        transcript.challenge()
    }

    fn update(&mut self, bytes: &[u8]) {
        self.hasher.update(&(bytes.len() as u64).to_be_bytes());
        self.hasher.update(bytes);
    }

    /// Adds a point to the transcript.
    pub(crate) fn add_element(&mut self, element: &C::Point) {
        let bytes = C::encode_point_for_transcript(element);
        self.update(bytes.as_ref());
    }

    /// Adds multiple points to the transcript.
    pub(crate) fn add_elements<'a>(&mut self, elements: impl Iterator<Item = &'a C::Point>)
    where
        C::Point: 'a,
    {
        for element in elements {
            self.add_element(element);
        }
    }

    /// Adds a scalar value to the transcript.
    pub(crate) fn add_scalar(&mut self, scalar: &C::Scalar) {
        let bytes = C::scalar_to_bytes(scalar);
        self.update(&bytes);
    }

    /// Adds multiple scalar values to the transcript.
    pub(crate) fn add_scalars<'a>(&mut self, scalars: impl Iterator<Item = &'a C::Scalar>)
    where
        C::Scalar: 'a,
    {
        for scalar in scalars {
            self.add_scalar(scalar);
        }
    }

    /// Generates a challenge scalar from the current transcript state.
    pub(crate) fn challenge(self) -> C::Scalar {
        C::challenge_from_hasher(self.hasher)
    }
}
