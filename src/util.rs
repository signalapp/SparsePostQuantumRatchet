// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// From libcrux-ml-kem/src/constant_time_ops.rs

/// Return 1 if `value` is not zero and 0 otherwise.
fn inz(value: u8) -> u8 {
    let value = value as u16;

    let result = ((value | (!value).wrapping_add(1)) >> 8) & 1;

    result as u8
}

#[inline(never)] // Don't inline this to avoid that the compiler optimizes this out.
fn is_non_zero(value: u8) -> u8 {
    core::hint::black_box(inz(value))
}

/// Return 1 if the bytes of `lhs` and `rhs` do not exactly
/// match and 0 otherwise.
#[cfg_attr(hax, hax_lib::requires(
    lhs.len() == rhs.len()
))]
pub(crate) fn compare(lhs: &[u8], rhs: &[u8]) -> u8 {
    let mut r: u8 = 0;

    for i in 0..lhs.len() {
        r |= lhs[i] ^ rhs[i];
    }

    is_non_zero(r)
}
