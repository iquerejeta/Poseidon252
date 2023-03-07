// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Sponge hash and gadget definition

use crate::sponge;
use bls12_381::{Scalar as BlsScalar};
use jubjub::{Scalar as JubJubScalar};

/// The constant represents the bitmask used to truncate the hashing results of
/// a sponge application so that they fit inside of a
/// [`JubJubScalar`] and it's equal to `2^250 - 1`.
///
/// Let the bitmask size be `m`
/// Considering the field size of jubjub is 251 bits, `m < 251`
/// Plonk logical gates will accept only even `m + 1`, so `(m + 1) % 2 == 0`
///
/// Plonk logical gates will perform the operation from the base bls `r` of
/// 255 bits + 1. `d = r + 1 - (m + 1) = 4`. But, `d = 4` don't respect the
/// previously set constraint, so it must be 6.
///
/// This way, the scalar will be truncated to `m = r - d = 255 - 6 = 249
/// bits`
const TRUNCATION_LIMIT: BlsScalar = BlsScalar::from_raw([
    0x432667a3f7cfca74,
    0x7905486e121a84be,
    0x19c02884cfe90d12,
    0xa62ffba6a1323be,
]);

/// Applies [`hash`] to the `messages` received truncating the result to
/// make it fit inside a `JubJubScalar.`
///
/// [`hash`]: crate::sponge::hash
pub fn hash(messages: &[BlsScalar]) -> JubJubScalar {
    // Putting here the implementation of `BitAnd` available in dusk-network's lib. https://github.com/dusk-network/bls12_381/blob/master/src/scalar.rs#L286
    // todo: Why are they doing this?
    let sponge_result = sponge::hash(messages).to_bytes();
    let trunc_lim = TRUNCATION_LIMIT.to_bytes();
    let mut result = [0u8; 32];
    result.copy_from_slice(&sponge_result.iter().zip(trunc_lim.iter()).map(|(res, lim)| res & lim).collect::<Vec<u8>>());
    JubJubScalar::from_bytes(
        &result
    ).unwrap()
}
