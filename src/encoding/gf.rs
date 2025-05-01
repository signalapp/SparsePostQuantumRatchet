// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

use std::ops;

// https://web.eecs.utk.edu/~jplank/plank/papers/CS-07-593/primitive-polynomial-table.txt
pub const POLY: u32 = 0x1100b; // 0o210013

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[repr(transparent)]
#[hax_lib::fstar::after(
    r#"
    let to_gf (s: t_GF16) = Spec.GF16.to_bv s.f_value
"#
)]
pub struct GF16 {
    pub value: u16,
}

#[hax_lib::attributes]
impl ops::AddAssign<&GF16> for GF16 {
    #[allow(clippy::suspicious_op_assign_impl)]
    #[requires(true)]
    #[hax_lib::ensures(|result| fstar!(r#"
        to_gf self_e_future == 
        Spec.GF16.gf_add (to_gf self_) (to_gf other)
    "#))]
    fn add_assign(&mut self, other: &Self) {
        hax_lib::fstar!("Spec.GF16.xor_is_gf_add_lemma self.f_value other.f_value");
        self.value ^= other.value;
    }
}

#[hax_lib::attributes]
impl ops::AddAssign for GF16 {
    #[hax_lib::ensures(|result| fstar!(r#"
        to_gf self_e_future == 
        Spec.GF16.gf_add (to_gf self_) (to_gf other)
    "#))]
    fn add_assign(&mut self, other: Self) {
        hax_lib::fstar!("Spec.GF16.xor_is_gf_add_lemma self.f_value other.f_value");
        self.add_assign(&other);
    }
}

#[hax_lib::attributes]
impl ops::Add for GF16 {
    type Output = Self;
    #[hax_lib::ensures(|result| fstar!(r#"
        to_gf result == 
        Spec.GF16.gf_add (to_gf self_) (to_gf other)
    "#))]
    fn add(self, other: Self) -> Self {
        let mut out = self;
        out += &other;
        out
    }
}

#[hax_lib::attributes]
impl ops::Add<&GF16> for GF16 {
    type Output = Self;
    #[hax_lib::ensures(|result| fstar!(r#"
        to_gf result == 
        Spec.GF16.gf_add (to_gf self_) (to_gf other)
    "#))]
    fn add(self, other: &Self) -> Self {
        let mut out = self;
        out += other;
        out
    }
}

#[hax_lib::attributes]
impl ops::SubAssign<&GF16> for GF16 {
    #[allow(clippy::suspicious_op_assign_impl)]
    #[hax_lib::ensures(|result| fstar!(r#"
        to_gf self_e_future == 
        Spec.GF16.gf_sub (to_gf self_) (to_gf other)
    "#))]
    fn sub_assign(&mut self, other: &Self) {
        *self += other;
    }
}

#[hax_lib::attributes]
impl ops::SubAssign for GF16 {
    #[hax_lib::ensures(|result| fstar!(r#"
        to_gf self_e_future == 
        Spec.GF16.gf_sub (to_gf self_) (to_gf other)
    "#))]
    fn sub_assign(&mut self, other: Self) {
        self.sub_assign(&other);
    }
}

#[hax_lib::attributes]
impl ops::Sub for GF16 {
    type Output = Self;
    #[hax_lib::ensures(|result| fstar!(r#"
        to_gf result == 
        Spec.GF16.gf_sub (to_gf self_) (to_gf other)
    "#))]
    fn sub(self, other: Self) -> Self {
        let mut out = self;
        out -= &other;
        out
    }
}

#[hax_lib::attributes]
impl ops::Sub<&GF16> for GF16 {
    type Output = Self;
    #[hax_lib::ensures(|result| fstar!(r#"
        to_gf result == 
        Spec.GF16.gf_sub (to_gf self_) (to_gf other)
    "#))]
    fn sub(self, other: &Self) -> Self {
        let mut out = self;
        out -= other;
        out
    }
}

#[hax_lib::attributes]
impl ops::MulAssign<&GF16> for GF16 {
    fn mul_assign(&mut self, other: &Self) {
        #[cfg(all(
            not(hax),
            any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")
        ))]
        if check_accelerated::TOKEN.get() {
            self.value = accelerated::mul(self.value, other.value);
            return;
        }
        self.value = unaccelerated::mul(self.value, other.value);
    }
}

#[hax_lib::attributes]
impl ops::MulAssign for GF16 {
    fn mul_assign(&mut self, other: Self) {
        self.mul_assign(&other);
    }
}

#[hax_lib::attributes]
impl ops::Mul for GF16 {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        let mut out = self;
        out *= &other;
        out
    }
}

#[hax_lib::attributes]
impl ops::Mul<&GF16> for GF16 {
    type Output = Self;
    fn mul(self, other: &Self) -> Self {
        let mut out = self;
        out *= other;
        out
    }
}

#[hax_lib::attributes]
impl ops::DivAssign<&GF16> for GF16 {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn div_assign(&mut self, other: &Self) {
        *self = self.div_impl(other);
    }
}

#[hax_lib::attributes]
impl ops::DivAssign for GF16 {
    fn div_assign(&mut self, other: Self) {
        *self = self.div_impl(&other);
    }
}

#[hax_lib::attributes]
impl ops::Div for GF16 {
    type Output = Self;
    fn div(self, other: Self) -> Self {
        self.div_impl(&other)
    }
}

#[hax_lib::attributes]
impl ops::Div<&GF16> for GF16 {
    type Output = Self;
    fn div(self, other: &Self) -> Self {
        self.div_impl(other)
    }
}

#[inline]
#[hax_lib::opaque]
pub fn parallel_mult(a: GF16, into: &mut [GF16]) {
    let mut i = 0;
    while i + 2 <= into.len() {
        hax_lib::loop_decreases!(into.len() - i);
        (into[i].value, into[i + 1].value) = mul2_u16(a.value, into[i].value, into[i + 1].value);
        i += 2;
    }
    if i < into.len() {
        into[i] *= a;
    }
}

#[hax_lib::opaque]
fn mul2_u16(a: u16, b1: u16, b2: u16) -> (u16, u16) {
    #[cfg(all(
        not(hax),
        any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")
    ))]
    if check_accelerated::TOKEN.get() {
        return accelerated::mul2(a, b1, b2);
    }
    (unaccelerated::mul(a, b1), unaccelerated::mul(a, b2))
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod accelerated {
    #[cfg(target_arch = "x86")]
    use core::arch::x86 as arch;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64 as arch;

    pub fn mul(a: u16, b: u16) -> u16 {
        mul2(a, b, 0).0
    }

    #[inline]
    #[target_feature(enable = "pclmulqdq")]
    unsafe fn mul2_unreduced(a: u16, b1: u16, b2: u16) -> (u32, u32) {
        let a = arch::_mm_set_epi64x(0, a as i64);
        let b = arch::_mm_set_epi64x(0, ((b2 as i64) << 32) | (b1 as i64));
        let clmul = arch::_mm_clmulepi64_si128(a, b, 0);

        // Some architectures have _mm_cvtsi128_si64, which pulls out the full 64
        // bits at once.  However, more architectures have _mm_cvtsi128_si32, which
        // just pulls out 32, and it turns out that doing that twice appears to have
        // about the same latency.
        let b1out = arch::_mm_cvtsi128_si32(clmul) as u32;
        // To pull out the higher bits (for b2), shift our result right by 4 bytes
        // (32 bits), then pull out the lowest 32 bits.
        let b2out = arch::_mm_cvtsi128_si32(arch::_mm_srli_si128(clmul, 4)) as u32;
        (b1out, b2out)
    }

    pub fn mul2(a: u16, b1: u16, b2: u16) -> (u16, u16) {
        let unreduced_products = unsafe { mul2_unreduced(a, b1, b2) };
        (
            super::reduce::poly_reduce(unreduced_products.0),
            super::reduce::poly_reduce(unreduced_products.1),
        )
    }
}

#[cfg(target_arch = "aarch64")]
mod accelerated {
    use core::arch::aarch64;

    pub fn mul(a: u16, b: u16) -> u16 {
        mul2(a, b, 0).0
    }

    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn mul2_unreduced(a: u16, b1: u16, b2: u16) -> u128 {
        aarch64::vmull_p64(a as u64, ((b1 as u64) << 32) | (b2 as u64))
    }

    pub fn mul2(a: u16, b1: u16, b2: u16) -> (u16, u16) {
        let unreduced_product = unsafe { mul2_unreduced(a, b1, b2) };
        (
            super::reduce::poly_reduce((unreduced_product >> 32) as u32),
            super::reduce::poly_reduce(unreduced_product as u32),
        )
    }
}

/*
#[cfg(target_arch = "arm")]
mod accelerated {
    use core::arch::arm;

    pub fn mul(a: u16, b: u16) -> u16 {
        mul2(a, b, 0).0
    }

    pub fn mul2(a: u16, b1: u16, b2: u16) -> (u16, u16) {
        // 32-bit ARM only provides polynomial multiplication of 8-bit
        // values, but it does provide _parallel_ multiplication of those values.
        // We use this to implement simple long-multiplication, in the form:
        //      AB
        //     *CD
        //  ------
        //      BD // 0 shifts
        //  +  BC  // 1 shift
        //  +  AD  // 1 shift
        //  + AC   // 2 shifts
        //
        // We use vmull_p8 to compute all sub-multiplications, then
        // XOR the results together with appropriate shifts to get the final
        // result.

        let a_mul = [
            (a >> 8) as u8,
            (a >> 8) as u8,
            (a & 0xff) as u8,
            (a & 0xff) as u8,
            (a >> 8) as u8,
            (a >> 8) as u8,
            (a & 0xff) as u8,
            (a & 0xff) as u8,
        ];
        let b_mul = [
            (b1 >> 8) as u8,
            (b1 & 0xff) as u8,
            (b1 >> 8) as u8,
            (b1 & 0xff) as u8,
            (b2 >> 8) as u8,
            (b2 & 0xff) as u8,
            (b2 >> 8) as u8,
            (b2 & 0xff) as u8,
        ];
        let out = unsafe {
            let a_p8 = arm::vld1_p8(&a_mul as *const u8);
            let b_p8 = arm::vld1_p8(&b_mul as *const u8);
            let ab_p16 = arm::vmull_p8(a_p8, b_p8);
            let mut out = [0u16; 8];
            arm::vst1q_p16(&mut out as *mut u16, ab_p16);
            out
        };
        let (b1out, b2out) = (
            ((out[0] as u32) << 16)
                ^ ((out[1] as u32) << 8)
                ^ ((out[2] as u32) << 8)
                ^ (out[3] as u32),
            ((out[4] as u32) << 16)
                ^ ((out[5] as u32) << 8)
                ^ ((out[6] as u32) << 8)
                ^ (out[7] as u32),
        );
        (
            super::reduce::poly_reduce(b1out),
            super::reduce::poly_reduce(b2out),
        )
    }
}
*/

#[cfg(all(
    not(hax),
    any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")
))]
mod check_accelerated {
    #[cfg(target_arch = "aarch64")]
    cpufeatures::new!(use_accelerated, "aes"); // `aes` implies PMULL
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    cpufeatures::new!(use_accelerated, "pclmulqdq");

    use std::sync::LazyLock;

    pub(crate) static TOKEN: LazyLock<use_accelerated::InitToken> =
        LazyLock::new(use_accelerated::init);
}

mod unaccelerated {
    #[hax_lib::fstar::options("--fuel 2")]
    #[hax_lib::ensures(|result| fstar!(r#"
        let open Spec.GF16 in
        to_bv result == 
        poly_mul (to_bv a) (to_bv b)"#))]
    const fn poly_mul(a: u16, b: u16) -> u32 {
        let mut acc: u32 = 0;
        let me = a as u32;
        // Long multiplication.
        let mut shift: u32 = 0;
        hax_lib::fstar!(
            r#"
            let open Spec.GF16 in
            assert_norm Spec.GF16.(poly_mul_i (to_bv a) (to_bv b) 0 == zero #32);
            zero_lemma #U32;
            up_cast_lemma #U16 #U32 a
        "#
        );
        while shift < 16 {
            hax_lib::loop_invariant!(fstar!(
                r#"
                let open Spec.GF16 in
                v shift <= 16 /\
                to_bv acc == poly_mul_i (to_bv a) (to_bv b) (v shift)
                "#
            ));
            hax_lib::loop_decreases!(16 - shift);
            hax_lib::fstar!(
                r#"
                let open Spec.GF16 in
                shift_left_bit_select_lemma b shift;
                up_cast_shift_left_lemma a shift;
                lemma_add_lift #(16+v shift) #32 (poly_mul_x_k (to_bv a) (v shift)) (to_bv acc);
                xor_is_gf_add_lemma acc (me <<! shift)
            "#
            );
            if 0 != b & (1 << shift) {
                hax_lib::fstar!(
                    r#" 
                    let open Spec.GF16 in
                    assert ((to_bv b).[v shift] == true);
                    assert (poly_mul_i (to_bv a) (to_bv b) (v shift + 1) ==
                             gf_add (poly_mul_i (to_bv a) (to_bv b) (v shift))
                                    (poly_mul_x_k (to_bv a) (v shift)))
                "#
                );
                acc ^= me << shift;
            }
            shift += 1;
        }
        acc
    }

    #[allow(dead_code)]
    #[hax_lib::ensures(|result| fstar!(r#"
        let open Spec.GF16 in
        let (r1, r2) = result in
        to_bv r1 == gf16_mul (to_bv a) (to_bv b1) /\
        to_bv r2 == gf16_mul (to_bv a) (to_bv b2)
    "#))]
    pub fn mul2(a: u16, b1: u16, b2: u16) -> (u16, u16) {
        (mul(a, b1), mul(a, b2))
    }

    #[hax_lib::ensures(|result| fstar!(r#"
        let open Spec.GF16 in
        to_bv result == 
        gf16_mul (to_bv a) (to_bv b)"#))]
    pub const fn mul(a: u16, b: u16) -> u16 {
        super::reduce::poly_reduce(poly_mul(a, b))
    }
}

mod reduce {
    use super::POLY;

    /// This is a somewhat optimized reduction that's architecture-agnostic.
    /// When reducing, we look from the highest- to lowest-order bits in the
    /// range 31..16, and we clear each 1 we find by XOR-ing with the POLY,
    /// whose topmost bit (1<<16) is set.  POLY is 17 bit long, meaning that
    /// we clear the topmost bit while affecting the 16 bits below it.
    /// Now, let's consider the topmost BYTE of a u32.  Assuming that byte is
    /// some constant C, we will always perform the same set of (up to) 8
    /// XORs on the 2 bytes below C, and these can be precompted as a 16-byte
    /// XOR against those bytes.  Also, once we're done processing C, we never
    /// use its data again, as we (correctly) assume that it will be zero'd out.
    /// So, given the (big-endian) u32 with bytes Cxyz, no matter what xyz are,
    /// we will always do:
    ///    Cxyz ^ Cab0 -> 0Dwz
    /// where the bytes `ab` are dependent entirely on C.  Assume again that
    /// we now have a new u32 with bytes 0Dwz.  We will again XOR this based
    /// entirely on the bits in D, and it will look something like:
    ///    0Dwz ^ 0Def -> 00uv
    /// where again, `ef` is dependent on D.  And, if D==C, then ef==ab.
    /// Note as well that since we never look at the high order bits again,
    /// the XORs by C and D are unnecessary.  Rather than:
    ///    Cxyz ^ Cab0 -> 0Dwz
    /// we can do:
    ///    Cxyz ^ 0ab0 -> CDwz
    /// then:
    ///    CDwz ^ 00ef -> CDuv
    /// as we're just going to return the lowest 16 bits to the caller.
    /// Given that we're doing this byte-by-byte and there's only 256 total
    /// potential bytes, we precompute all XORs into the REDUCE_BYTES
    /// buffer.  In the above example:
    ///   REDUCE_BYTES[C] -> ab
    ///   REDUCE_BYTES[D] -> ef
    /// Since we're mapping every byte to a u16, we take up 512B of space
    /// to do this, and our reduction is just a couple of pipelined shifts/XORs.
    #[hax_lib::fstar::verification_status(panic_free)]
    #[hax_lib::ensures(|result| fstar!(r#"
        Spec.GF16.(to_bv result == poly_reduce #gf16 (to_bv v))
        "#))]
    pub const fn poly_reduce(v: u32) -> u16 {
        let mut v = v;
        let i1 = (v >> 24) as usize;
        v ^= (REDUCE_BYTES[i1] as u32) << 8;
        let shifted_v = (v >> 16) as usize;
        let i2 = shifted_v & 0xFF;
        hax_lib::fstar!("logand_lemma $shifted_v (mk_usize 255)");
        v ^= REDUCE_BYTES[i2] as u32;
        v as u16
    }

    /// Compute the u16 reduction associated with u8 `a`.  See the comment
    /// in poly_reduce for more details.
    const fn reduce_from_byte(mut a: u8) -> u32 {
        let mut out = 0u32;
        let mut i: u32 = 8;
        while i > 0 {
            hax_lib::loop_invariant!(i <= 8);
            hax_lib::loop_decreases!(i);
            i -= 1;
            if (1 << i) & a != 0 {
                out ^= POLY << i;
                a ^= ((POLY << i) >> 16) as u8;
            }
        }
        out
    }

    /// Compute the u16 reductions for all bytes.  See the comment in
    /// poly_reduce for more details.
    const fn reduce_bytes() -> [u16; 256] {
        let mut out = [0u16; 256];
        let mut i = 0;
        while i < 256 {
            hax_lib::loop_invariant!(hax_lib::prop::constructors::and(
                (i <= 256).into(),
                hax_lib::forall(|j: usize| hax_lib::implies(
                    j < i,
                    out[j] == (reduce_from_byte(j as u8) as u16)
                ))
            ));
            hax_lib::loop_decreases!(256 - i);
            out[i] = reduce_from_byte(i as u8) as u16;
            i += 1;
        }
        out
    }

    const REDUCE_BYTES: [u16; 256] = reduce_bytes();
}

impl GF16 {
    pub const ZERO: Self = Self { value: 0 };
    pub const ONE: Self = Self { value: 1 };

    pub fn new(value: u16) -> Self {
        Self { value }
    }

    pub fn inv(&self) -> GF16 {
        GF16::ONE.div_impl(self)
    }

    fn div_impl(&self, other: &Self) -> Self {
        // Within GF(p^n), inv(a) == a^(p^n-2).  We're GF(2^16) == GF(65536),
        // so we can compute GF(65534).
        let mut square = *other * *other;
        let mut out = *self;
        for _i in 1..16 {
            (square.value, out.value) = mul2_u16(square.value, square.value, out.value);
        }
        out
    }

    pub const fn const_mul(&self, other: &Self) -> Self {
        Self {
            value: unaccelerated::mul(self.value, other.value),
        }
    }

    pub const fn const_sub(&self, other: &Self) -> Self {
        Self {
            value: self.value ^ other.value,
        }
    }

    pub const fn const_add(&self, other: &Self) -> Self {
        Self {
            value: self.value ^ other.value,
        }
    }

    pub const fn const_div(&self, other: &Self) -> Self {
        // Within GF(p^n), inv(a) == a^(p^n-2).  We're GF(2^16) == GF(65536),
        // so we can compute GF(65534).
        let mut square = *other;
        let mut out = *self;
        {
            // const for loop
            let mut i: usize = 1;
            while i < 16 {
                hax_lib::loop_invariant!(i <= 16);
                hax_lib::loop_decreases!(16 - i);
                square = square.const_mul(&square);
                out = out.const_mul(&square);
                i += 1;
            }
        }
        out
    }

    pub const fn const_inv(&self) -> GF16 {
        GF16::ONE.const_div(self)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use galois_field_2pm::gf2::GFu16;
    use galois_field_2pm::GaloisField;
    use rand::RngCore;

    // https://web.eecs.utk.edu/~jplank/plank/papers/CS-07-593/primitive-polynomial-table.txt
    type ExternalGF16 = GFu16<{ POLY as u128 }>;

    #[test]
    fn add() {
        let mut rng = rand::rng();
        for _i in 0..100 {
            let x = rng.next_u32() as u16;
            let y = rng.next_u32() as u16;
            assert_eq!(
                (GF16 { value: x } + GF16 { value: y }).value,
                (ExternalGF16::new(x) + ExternalGF16::new(y)).value
            );
        }
    }
    #[test]
    fn mul() {
        let mut rng = rand::rng();
        for _i in 0..100 {
            let x = rng.next_u32() as u16;
            let y = rng.next_u32() as u16;
            let a = (GF16 { value: x } * GF16 { value: y }).value;
            let b = (ExternalGF16::new(x) * ExternalGF16::new(y)).value;
            println!("{x:04x} * {y:04x} = {b:04x}");
            assert_eq!(a, b);
        }
    }
    #[test]
    fn inv() {
        let mut rng = rand::rng();
        for _i in 0..100 {
            let x = rng.next_u32() as u16;
            assert_eq!(
                (GF16 { value: x } * GF16 { value: x }.inv()).value,
                GF16::ONE.value
            );
        }
    }
    #[test]
    fn div() {
        let mut rng = rand::rng();
        for _i in 0..100 {
            let x = rng.next_u32() as u16;
            let y = rng.next_u32() as u16;
            if y == 0 {
                continue;
            }
            assert_eq!(
                (GF16 { value: x } / GF16 { value: y }).value,
                (ExternalGF16::new(x) / ExternalGF16::new(y)).value
            );
        }
    }
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2",))]
    #[test]
    fn x86_barrett_reduction() {
        // Barrett reduction.  Not noticeably faster than noarch::poly_reduce,
        // but left here for posterity.

        use super::POLY;
        const POLY_128: [u32; 4] = [POLY, 0, 0, 0]; // Little-endian
        const POLY_M128I: core::arch::x86_64::__m128i = unsafe { core::mem::transmute(POLY_128) };
        const POLY_BARRETT_REDUCTION: u32 = 0x1111a; // 2^32 / POLY with carryless division
        const POLYB_128: [u32; 4] = [POLY_BARRETT_REDUCTION, 0, 0, 0]; // Little-endian
        const POLYB_M128I: core::arch::x86_64::__m128i = unsafe { core::mem::transmute(POLYB_128) };
        let (a, b) = (0xf5u16, 0x93u16);

        // initial multiplication
        let unreduced_product = unsafe {
            let a = core::arch::x86_64::_mm_set_epi64x(0, a as i64);
            let b = core::arch::x86_64::_mm_set_epi64x(0, b as i64);
            core::arch::x86_64::_mm_clmulepi64_si128(a, b, 0)
        };
        let result = unsafe {
            // We perform a Barrett reduction with the precomputed POLYB=2^32/POLY,
            // manually computed via XOR-based long division.
            let quotient =
                core::arch::x86_64::_mm_clmulepi64_si128(unreduced_product, POLYB_M128I, 0);
            // We need to shift the quotient down 32 bits, so we'll do a register
            // shuffle.  We now the highest 32 bits of the 128b register are zero,
            // so we'll use those for the top 3 32-bit portions of the register.
            // So, given a 128-bit register with u32 values [0, a, b, c],
            // we end up with a register with [0, 0, 0, b].
            let quotient_shifted = core::arch::x86_64::_mm_shuffle_epi32(quotient, 0xf9);
            // Now that we have the quotient q=floor(a*b/POLY), we subtract
            // POLY*q from a*b to get the remainder:
            let subtrahend =
                core::arch::x86_64::_mm_clmulepi64_si128(POLY_M128I, quotient_shifted, 0);
            // Of course, our difference is computed using XOR
            core::arch::x86_64::_mm_cvtsi128_si64(core::arch::x86_64::_mm_xor_si128(
                unreduced_product,
                subtrahend,
            )) as u16
        };
        assert_eq!(
            result,
            super::reduce::poly_reduce(unsafe {
                core::arch::x86_64::_mm_cvtsi128_si64(unreduced_product)
            } as u32)
        );
    }
}
