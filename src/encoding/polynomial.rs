// Copyright 2025 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

use sorted_vec::SortedSet;

use super::{Chunk, Decoder, Encoder};

use crate::encoding::gf::{self, GF16};
use crate::proto;
use std::cmp::Ordering;

#[derive(Debug, thiserror::Error, Copy, Clone, PartialEq)]
pub enum PolynomialError {
    #[error("Message length must be divisible by 2")]
    MessageLengthEven,
    #[error("Message length is too long")]
    MessageLengthTooLong,
    #[error("Serialization invalid")]
    SerializationInvalid,
}

#[derive(Copy, Clone, Eq)]
/// Pt is an internal cartesian point for a function in the GF16
/// space.  It's mostly used to allow for lookup and ordering by
/// the X value in a BTreeSet.
struct Pt {
    x: GF16,
    y: GF16,
}

impl Pt {
    fn serialize(&self) -> [u8; 4] {
        let mut out = [0u8; 4];
        out[..2].clone_from_slice(&self.x.value.to_be_bytes()[..]);
        out[2..].clone_from_slice(&self.y.value.to_be_bytes()[..]);
        out
    }
    fn deserialize(s: [u8; 4]) -> Self {
        Self {
            x: GF16::new(u16::from_be_bytes(s[..2].try_into().unwrap())),
            y: GF16::new(u16::from_be_bytes(s[2..].try_into().unwrap())),
        }
    }
}

impl Ord for Pt {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

// TODO: Use a canonical implementation of Ord/PartialOrd once it works with hax
#[allow(clippy::non_canonical_partial_ord_impl)]
impl PartialOrd for Pt {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.x.value.cmp(&other.x.value))
    }
}

impl PartialEq for Pt {
    fn eq(&self, other: &Self) -> bool {
        self.x.value == other.x.value
    }
}

// The highest degree polynomial that will be stored for Protocol V1
pub const MAX_STORED_POLYNOMIAL_DEGREE_V1: usize = 35;

// The highest degree polynomial that will be constructed in intermediate
// calculations for Protocol V1
pub const MAX_INTERMEDIATE_POLYNOMIAL_DEGREE_V1: usize = 36;

#[derive(Clone, PartialEq)]
pub(crate) struct Poly {
    // For Protocol V1 we interpolate at most 36 values, which produces a
    // degree 35 polynomial (with 36 coefficients). In an intermediate calculation
    // during Lagrange interpolation, we need to compute a polynomial one degree
    // higher, thus we get the following constraint:
    //
    // coefficients.len() <= MAX_INTERMEDIATE_POLYNOMIAL_DEGREE_V1 + 1
    pub coefficients: Vec<GF16>,
}

#[hax_lib::attributes]
impl Poly {
    //
    // capacity <= MAX_INTERMEDIATE_POLYNOMIAL_DEGREE_V1 + 1
    fn zero(capacity: usize) -> Self {
        Self {
            coefficients: Vec::with_capacity(capacity),
        }
    }

    /// Given a set of points with unique X values, return a Poly that
    /// computes f(pts[i].x) == pts[i].y for all points.
    ///
    /// This takes O(N^2) work and O(N) space, carefully allocated up
    /// front to avoid overhead.
    #[hax_lib::requires(pts.len() <= MAX_INTERMEDIATE_POLYNOMIAL_DEGREE_V1)]
    fn lagrange_interpolate(pts: &[Pt]) -> Self {
        let mut out = Self::zero(pts.len());
        if pts.is_empty() {
            return out;
        }

        let template = Self::lagrange_interpolate_prepare(pts);
        let mut working = template.clone();

        // Unroll the first loop to skip some unnecessary work.
        working.lagrange_interpolate_complete(pts, 0);
        // Note that `working` is `x * <the polynomial we need>`.
        out.coefficients
            .extend_from_slice(&working.coefficients[1..]);

        let _w_l = working.coefficients.len();
        for i in 1..pts.len() {
            hax_lib::loop_invariant!(
                |_: usize| out.coefficients.len() == _w_l - 1 && working.coefficients.len() == _w_l
            );
            working.coefficients.copy_from_slice(&template.coefficients);
            working.lagrange_interpolate_complete(pts, i);
            // We can't use `add_assign` because `working` is `x * <the polynomial we need>`.
            // Removing the lowest coefficient would cost a memmove.
            // So we just skip it in this loop to effectively "divide by x".
            for j in 0..out.coefficients.len() {
                hax_lib::loop_invariant!(|_: usize| out.coefficients.len() == _w_l - 1);
                out.coefficients[j] += working.coefficients[j + 1];
            }
        }
        out
    }

    /// Computes `PRODUCT(x - pi.x)` as part of Lagrange interpolation.
    ///
    /// This takes O(N^2) work: for each of N points, we are multiplying every coefficient of a
    /// 1..N-degree polynomial.
    #[hax_lib::requires(pts.len() <= MAX_INTERMEDIATE_POLYNOMIAL_DEGREE_V1)]
    fn lagrange_interpolate_prepare(pts: &[Pt]) -> Self {
        // We're going to fill in the coefficients from largest to smallest, so we start by putting
        // a 1 in the *highest* field rather than the lowest. This lets us avoid sliding
        // coefficients as we go, but it also means we have to track the offset of which
        // coefficients have been initialized manually.
        let mut p = Self::zero(pts.len() + 1);
        p.coefficients.resize(pts.len() + 1, GF16::ZERO);
        let offset = pts.len();
        p.coefficients[offset] = GF16::ONE;

        #[allow(clippy::needless_range_loop)]
        for i in 0..offset {
            hax_lib::loop_invariant!(|_: usize| p.coefficients.len() == offset + 1);
            let pi = pts[i];
            p.mult_xdiff_assign_trailing(offset - i, pi.x);
        }
        #[cfg(not(hax))]
        debug_assert_eq!(p.coefficients[pts.len()], GF16::ONE);
        p
    }

    /// self[start..] *= (x - difference)
    ///
    /// Interprets the trailing N coefficients as a smaller polynomial, and multiplies *that*
    /// polynomial by `(x - difference)`, with the "carry" propagating into self[start-1]. This
    /// works because (x-d)(poly) = x*poly - d*poly.
    ///
    /// This allows us to build up a polynomial from its *largest* coefficient, and thus avoid
    /// sliding coefficients in the vector as we go.
    #[hax_lib::requires(0 < start && start <= self.coefficients.len())]
    fn mult_xdiff_assign_trailing(&mut self, start: usize, difference: GF16) {
        let l = self.coefficients.len();
        for i in start..l {
            hax_lib::loop_invariant!(|_: usize| self.coefficients.len() == l);
            let delta = self.coefficients[i] * difference;
            self.coefficients[i - 1] -= delta;
        }
    }

    /// Given `PRODUCT(x - pi.x)`, creates something very close to the Lagrange poly for `pts[i]` in
    /// `pts`.
    ///
    /// This computes `f(pts[i].x) == pts[i].y`, and `f(pts[*].x) == 0` for all other points. It
    /// does so by first dividing out the specific `(x - pi.x)` we care about, then scaling so that
    /// the remaining polynomial produces `pi.y` at `pi.x`.
    ///
    /// However, due to our representation, the result we actually end up with is scaled by `x`.
    /// It's cheaper to have callers deal with that manually than to adjust it here, though.
    ///
    /// This does O(N) work: one loop over the coefficients to divide out the term we need, one loop
    /// over the points to calculate the scaling factor, and then one final loop to scale the
    /// coefficients.
    #[hax_lib::requires(i < pts.len())]
    fn lagrange_interpolate_complete(&mut self, pts: &[Pt], i: usize) {
        let pi = &pts[i];

        // Compute the scaling factor.
        let mut denominator = GF16::ONE;
        for pj in pts {
            if pi.x == pj.x {
                continue;
            }
            denominator *= pi.x - pj.x;
        }
        let scale = pi.y / denominator;

        // Divide out (x - pi.x) using plain old long division, and scale as we go.
        // This avoids having to reload the same value from memory twice.
        // Remember our coefficients are in little-endian order, so we start from the end.
        let _init_l = self.coefficients.len();
        for j in 1..self.coefficients.len() {
            hax_lib::loop_invariant!(|_: usize| self.coefficients.len() == _init_l);
            let i = self.coefficients.len() - j;
            let negative_delta = self.coefficients[i] * pi.x;
            self.coefficients[i] *= scale;
            self.coefficients[i - 1] += negative_delta;
        }
        #[cfg(not(hax))]
        debug_assert_eq!(self.coefficients[0], GF16::ZERO, "should divide cleanly");
    }

    /// Create the Lagrange poly for `pts[i]` in `pts`, which computes
    /// f(pts[i].x) == f(pts[i].y), and f(pts[*].x) == 0 for all other points.
    ///
    /// This interface is used only as a fallback for encoding; we do not rely
    /// on it for speed, so it's okay that it's doing a bit of extra work.
    #[hax_lib::requires(pts.len() <= MAX_INTERMEDIATE_POLYNOMIAL_DEGREE_V1 && i < pts.len())]
    fn lagrange_interpolate_pt(pts: &[Pt], i: usize) -> Self {
        let mut result = Self::lagrange_interpolate_prepare(pts);
        result.lagrange_interpolate_complete(pts, i);
        result.coefficients.remove(0);
        result
    }

    /// self += other
    fn add_assign(&mut self, other: &Self) {
        for (i, v) in other.coefficients.iter().enumerate() {
            if i < self.coefficients.len() {
                self.coefficients[i] += *v;
            } else {
                self.coefficients.push(*v);
            }
        }
    }

    /// self *= m
    fn mult_assign(&mut self, m: GF16) {
        gf::parallel_mult(m, &mut self.coefficients);
    }

    fn compute_at(&self, x: GF16) -> GF16 {
        // Compute x^0 .. x^N
        let mut xs = Vec::with_capacity(self.coefficients.len());
        xs.push(GF16::ONE);
        xs.push(x);
        for i in 2..self.coefficients.len() {
            hax_lib::loop_invariant!(|i: usize| i == xs.len() && i / 2 < i && i >= 2);
            let a = xs[i / 2];
            let b = xs[(i / 2) + (i % 2)];
            xs.push(a * b);
        }
        // Multiply and sum
        let mut out = GF16::ZERO;
        for (a, b) in self.coefficients.iter().zip(xs.iter()) {
            out += *a * *b;
        }
        out
    }

    /// Internal function for lagrange_polynomial_from_complete_points.
    fn lagrange_sum(pts: &[Pt], polys: &[Poly]) -> Poly {
        let mut out = Poly::zero(pts.len());
        for (pt, poly) in pts.iter().zip(polys.iter()) {
            let mut p = poly.clone();
            p.mult_assign(pt.y);
            out.add_assign(&p);
        }
        out
    }

    /// Given a set of "complete" points with x values that fully fill the
    /// range [0..pts.len()), return a polynomial that computes those points.
    #[hax_lib::requires(pts.len() == 0 || pts.len() == 1 || pts.len() == 3 || pts.len() == 5
    || pts.len() == 30 || pts.len() == 34 || pts.len() == 36)]
    fn from_complete_points(pts: &[Pt]) -> Result<Poly, ()> {
        for (i, pt) in pts.iter().enumerate() {
            if pt.x.value != i as u16 {
                return Err(());
            }
        }
        // The `as u64` is for hax.
        // The following constraint holds for Protocol V1
        // polys.len() <= MAX_STORED_POLYNOMIAL_DEGREE_V1 + 1
        let polys = match pts.len() as u64 {
            0 => vec![],
            1 => const_polys_to_polys(&COMPLETE_POINTS_POLYS_1),
            3 => const_polys_to_polys(&COMPLETE_POINTS_POLYS_3),
            5 => const_polys_to_polys(&COMPLETE_POINTS_POLYS_5),
            30 => const_polys_to_polys(&COMPLETE_POINTS_POLYS_30),
            34 => const_polys_to_polys(&COMPLETE_POINTS_POLYS_34),
            36 => const_polys_to_polys(&COMPLETE_POINTS_POLYS_36),
            _ => {
                debug_assert!(false, "missing precomputed poly of size {}", pts.len());
                let ones = pts
                    .iter()
                    .map(|pt| Pt {
                        x: pt.x,
                        y: GF16::ONE,
                    })
                    .collect::<Vec<_>>();
                pts.iter()
                    .enumerate()
                    .map(|(i, _pt)| Self::lagrange_interpolate_pt(&ones, i))
                    .collect::<Vec<_>>()
            }
        };
        Ok(Self::lagrange_sum(pts, &polys))
    }

    #[hax_lib::requires(self.coefficients.len() <= MAX_INTERMEDIATE_POLYNOMIAL_DEGREE_V1)]
    pub fn serialize(&self) -> Vec<u8> {
        // For Protocol V1 the polynomials that get serialized will always have
        // coefficients.len() <= MAX_STORED_POLYNOMIAL_DEGREE_V1 + 1
        let mut out = Vec::<u8>::with_capacity(self.coefficients.len() * 2);
        for i in 0..self.coefficients.len() {
            hax_lib::loop_invariant!(|i: usize| out.len() == 2 * i);
            let c = self.coefficients[i];
            out.extend_from_slice(&c.value.to_be_bytes()[..]);
        }

        out
    }

    pub fn deserialize(serialized: &[u8]) -> Result<Self, PolynomialError> {
        if serialized.is_empty() || serialized.len() % 2 == 1 {
            return Err(PolynomialError::SerializationInvalid);
        }
        let mut coefficients = Vec::<GF16>::with_capacity(serialized.len() / 2);
        for coeff in serialized.chunks_exact(2) {
            coefficients.push(GF16::new(u16::from_be_bytes(coeff.try_into().unwrap())));
        }
        Ok(Self { coefficients })
    }
}

// For Protocol V1 with MLKEM-768: N <= MAX_STORED_POLYNOMIAL_DEGREE_V1 + 1
struct PolyConst<const N: usize> {
    coefficients: [GF16; N],
}

#[hax_lib::attributes]
impl<const N: usize> PolyConst<N> {
    const ZEROS: Self = Self {
        coefficients: [GF16::ZERO; N],
    };

    /// Create the Lagrange poly for `pts[i]` in `pts`, which computes
    /// f(pts[i].x) == pts[i].y, and f(pts[*].x) == 0 for all other points.
    #[hax_lib::requires(i < N && pts.len() >= N && N > 0)]
    const fn lagrange_interpolate_pt(pts: &[Pt], i: usize) -> Self {
        let pi = &pts[i];
        let mut p = Self {
            coefficients: [GF16::ZERO; N],
        };
        p.coefficients[0] = GF16::ONE;
        let mut denominator = GF16::ONE;
        {
            // const for loop
            let mut j: usize = 0;
            while j < N {
                hax_lib::loop_invariant!(j <= N);
                hax_lib::loop_decreases!(N - j);
                let pj = &pts[j];
                j += 1;
                if pi.x.value == pj.x.value {
                    continue;
                }
                // p.coefficients[N - 1].value == 0
                p = p.mult_xdiff(pj.x);
                denominator = denominator.const_mul(&pi.x.const_sub(&pj.x));
            }
        }
        // mul_assign(pi.y / denominator)
        p.mult(pi.y.const_div(&denominator))
    }

    /// self * m
    const fn mult(&self, m: GF16) -> Self {
        let mut i: usize = 0;
        let mut out = Self {
            coefficients: self.coefficients,
        };
        while i < N {
            hax_lib::loop_invariant!(i <= N);
            hax_lib::loop_decreases!(N - i);
            out.coefficients[i] = out.coefficients[i].const_mul(&m);
            i += 1;
        }
        out
    }

    /// self * (x - difference)
    // #[hax_lib::requires(N > 0 && self.coefficients[N - 1].value == 0)]
    #[hax_lib::opaque] // The precondition above is needed to prove panic freedom here but hard to prove for calls
    const fn mult_xdiff(&self, difference: GF16) -> Self {
        // Because we're constant-sized, we can't overflow, so check in advance
        // that we won't.
        if self.coefficients[N - 1].value != 0 {
            panic!("overflow in const mult_xdiff");
        }
        // We're multiplying (x-d)(poly), so we distribute that
        // into two operations:  x*poly - d*poly.
        // We'll store the first in xp and the second in dp.
        let mut xp = [GF16::ZERO; N];
        let mut dp = [GF16::ZERO; N];

        {
            // const for loop
            let mut i: usize = 0;
            while i < N {
                hax_lib::loop_invariant!(i <= N);
                hax_lib::loop_decreases!(N - i);
                // First, we make xp[*] into x*poly.  This simply shifts the coefficients over by one.
                if i < N - 1 {
                    xp[i + 1] = self.coefficients[i];
                }
                // Then, we make dp[*] into d*poly.
                dp[i] = self.coefficients[i].const_mul(&difference);
                i += 1;
            }
        }
        // Finally, we subtract: x*poly - d*poly -> xp[*] - dp[*]
        {
            // const for loop
            let mut i: usize = 0;
            while i < N {
                hax_lib::loop_invariant!(i <= N);
                hax_lib::loop_decreases!(N - i);
                xp[i] = xp[i].const_sub(&dp[i]);
                i += 1;
            }
        }
        Self { coefficients: xp }
    }

    fn to_poly(&self) -> Poly {
        Poly {
            coefficients: self.coefficients.to_vec(),
        }
    }
}

// For Protocol V1 N <= 36
fn const_polys_to_polys<const N: usize>(cps: &[PolyConst<N>; N]) -> Vec<Poly> {
    cps.iter().map(|x| x.to_poly()).collect::<Vec<_>>()
}

const fn lagrange_polys_for_complete_points<const N: usize>() -> [PolyConst<N>; N] {
    let mut ones = [Pt {
        x: GF16::ZERO,
        y: GF16::ONE,
    }; N];
    {
        // const for loop
        let mut i: usize = 0;
        while i < N {
            hax_lib::loop_invariant!(i <= N);
            hax_lib::loop_decreases!(N - i);
            ones[i].x.value = i as u16;
            i += 1;
        }
    }
    let mut out = [PolyConst::<N>::ZEROS; N];
    {
        // const for loop
        let mut i: usize = 0;
        while i < N {
            hax_lib::loop_invariant!(i <= N);
            hax_lib::loop_decreases!(N - i);
            out[i] = PolyConst::<N>::lagrange_interpolate_pt(&ones, i);
            i += 1;
        }
    }
    out
}

// Precompute Lagrange polynomials for each message size we need when running
// the v1 protocol using MLKEM-768 and when running tests.
const COMPLETE_POINTS_POLYS_1: [PolyConst<1>; 1] = lagrange_polys_for_complete_points::<1>();
const COMPLETE_POINTS_POLYS_3: [PolyConst<3>; 3] = lagrange_polys_for_complete_points::<3>();
const COMPLETE_POINTS_POLYS_5: [PolyConst<5>; 5] = lagrange_polys_for_complete_points::<5>();
const COMPLETE_POINTS_POLYS_30: [PolyConst<30>; 30] = lagrange_polys_for_complete_points::<30>();
const COMPLETE_POINTS_POLYS_34: [PolyConst<34>; 34] = lagrange_polys_for_complete_points::<34>();
const COMPLETE_POINTS_POLYS_36: [PolyConst<36>; 36] = lagrange_polys_for_complete_points::<36>();

// Size of a chunk in bytes
const CHUNK_SIZE: usize = 32;
// Number of polys or points that need to be tracked when using GF(2^16) with 2-byte elements
const NUM_POLYS: usize = CHUNK_SIZE / 2;

#[cfg_attr(test, derive(Clone))]
pub(crate) enum EncoderState {
    // For 32B chunks the outer vector has length 16.
    // Using MLKEM-768 the inner vector has length <= MAX_STORED_POLYNOMIAL_DEGREE_V1 + 1
    Points([Vec<GF16>; NUM_POLYS]),
    // For 32B chunks this vector has length 16.
    Polys([Poly; NUM_POLYS]),
}

#[cfg_attr(test, derive(Clone))]
pub struct PolyEncoder {
    idx: u32,
    s: EncoderState,
}

#[hax_lib::attributes]
impl PolyEncoder {
    #[allow(dead_code)] // used in hax annotations
    pub(crate) fn get_encoder_state(&self) -> &EncoderState {
        &self.s
    }

    #[hax_lib::requires(match self.s {
        EncoderState::Points(points) => hax_lib::Prop::from(points.len() == 16).and(hax_lib::prop::forall(|pts: &Vec<GF16>|
            hax_lib::prop::implies(points.contains(pts), pts.len() <= MAX_INTERMEDIATE_POLYNOMIAL_DEGREE_V1))),
        EncoderState::Polys(polys) => hax_lib::Prop::from(polys.len() == 16).and(hax_lib::prop::forall(|poly: &Poly|
            hax_lib::prop::implies(polys.contains(poly), poly.coefficients.len() <= MAX_INTERMEDIATE_POLYNOMIAL_DEGREE_V1)))
    })]
    pub fn into_pb(self) -> proto::pq_ratchet::PolynomialEncoder {
        let mut out = proto::pq_ratchet::PolynomialEncoder {
            idx: self.idx,
            pts: Vec::with_capacity(16),
            polys: Vec::with_capacity(16),
        };
        match self.s {
            EncoderState::Points(ref points) =>
            {
                #[allow(clippy::needless_range_loop)]
                for j in 0..points.len() {
                    hax_lib::loop_invariant!(|j: usize| out.pts.len() == j);
                    let pts = &points[j];
                    let mut v = Vec::<u8>::with_capacity(2 * pts.len());
                    #[allow(clippy::needless_range_loop)]
                    for i in 0..pts.len() {
                        hax_lib::loop_invariant!(|i: usize| v.len() == 2 * i);
                        let pt = pts[i];
                        v.extend_from_slice(&pt.value.to_be_bytes()[..]);
                    }
                    out.pts.push(v);
                }
            }
            EncoderState::Polys(ref polys) => {
                for poly in polys.iter() {
                    out.polys.push(poly.serialize());
                }
            }
        };
        out
    }

    pub fn from_pb(pb: proto::pq_ratchet::PolynomialEncoder) -> Result<Self, PolynomialError> {
        let s = if !pb.pts.is_empty() {
            if !pb.polys.is_empty() {
                return Err(PolynomialError::SerializationInvalid);
            }
            if pb.pts.len() != NUM_POLYS {
                return Err(PolynomialError::SerializationInvalid);
            }
            let mut out = core::array::from_fn(|_| Vec::<GF16>::new());

            #[allow(clippy::needless_range_loop)]
            for i in 0..NUM_POLYS {
                hax_lib::loop_invariant!(|_: usize| hax_lib::prop::forall(|pts: &Vec<GF16>| {
                    hax_lib::prop::implies(
                        out.contains(pts),
                        pts.len() <= MAX_INTERMEDIATE_POLYNOMIAL_DEGREE_V1,
                    )
                }));
                let pts = &pb.pts[i];
                if pts.len() % 2 != 0 {
                    return Err(PolynomialError::SerializationInvalid);
                }
                let mut v = Vec::<GF16>::with_capacity(pts.len());
                for pt in pts.chunks_exact(2) {
                    v.push(GF16::new(u16::from_be_bytes(pt.try_into().unwrap())));
                }
                out[i] = v;
            }
            EncoderState::Points(out)
        } else if pb.polys.len() == NUM_POLYS {
            let mut out: [Poly; NUM_POLYS] = core::array::from_fn(|_| Poly::zero(1));
            for (i, poly) in pb.polys.iter().enumerate() {
                out[i] = Poly::deserialize(poly)?;
            }
            EncoderState::Polys(out)
        } else {
            return Err(PolynomialError::SerializationInvalid);
        };
        Ok(Self { idx: pb.idx, s })
    }

    #[requires(poly < 16)]
    fn point_at(&mut self, poly: usize, idx: usize) -> GF16 {
        if let EncoderState::Points(ref pts) = self.s {
            hax_lib::assume!(pts.len() == 16);
            if idx < pts[poly].len() {
                return pts[poly][idx];
            }
            // If we reach here, we've come to the first point we want to
            // find that wasn't part of the original set of points.  We
            // assume that from here on, we're always going to have to compute
            // points, so we replace our set of points with an associated
            // set of polys that allow us to compute any point.
            let mut polys: [Poly; NUM_POLYS] = core::array::from_fn(|_| Poly::zero(1));
            for i in 0..NUM_POLYS {
                let pt_vec = pts[i]
                    .iter()
                    .enumerate()
                    .map(|(x, y)| Pt {
                        x: GF16::new(x as u16),
                        y: *y,
                    })
                    .collect::<Vec<Pt>>();
                hax_lib::assume!(
                    pt_vec.len() == 0
                        || pt_vec.len() == 1
                        || pt_vec.len() == 3
                        || pt_vec.len() == 5
                        || pt_vec.len() == 30
                        || pt_vec.len() == 34
                        || pt_vec.len() == 36
                );
                let res = Poly::from_complete_points(&pt_vec);
                hax_lib::assume!(res.is_ok());
                polys[i] = res.expect("pt_vec should be complete")
            }
            self.s = EncoderState::Polys(polys);
        }
        if let EncoderState::Polys(ref polys) = self.s {
            hax_lib::assume!(polys.len() == 16);
            polys[poly].compute_at(GF16::new(idx as u16))
        } else {
            panic!("if we reach here, we should have polys");
        }
    }

    fn encode_bytes_base(msg: &[u8]) -> Result<Self, super::EncodingError> {
        if msg.len() % 2 != 0 {
            return Err(PolynomialError::MessageLengthEven.into());
        } else if msg.len() > (1 << 16) * NUM_POLYS {
            return Err(PolynomialError::MessageLengthTooLong.into());
        }
        let mut pts: [Vec<GF16>; NUM_POLYS] =
            core::array::from_fn(|_| Vec::<GF16>::with_capacity(msg.len() / 2));
        for (i, c) in msg.chunks_exact(2).enumerate() {
            hax_lib::loop_invariant!(|_: usize| pts.len() >= NUM_POLYS);
            let poly = i % pts.len();
            pts[poly].push(GF16::new(((c[0] as u16) << 8) + (c[1] as u16)));
        }
        Ok(Self {
            idx: 0,
            s: EncoderState::Points(pts),
        })
    }

    // public for benchmarking
    pub fn chunk_at(&mut self, idx: u16) -> Chunk {
        let mut out = Vec::with_capacity(32);
        let _p = 16;
        for i in 0..16 {
            hax_lib::loop_invariant!(|i: usize| _p == 16 && out.len() == 2 * i);
            let total_idx = (idx as usize) * 16 + i;
            let poly = total_idx % 16;
            let poly_idx = total_idx / 16;
            let p = self.point_at(poly, poly_idx).value;
            out.push((p >> 8) as u8);
            out.push(p as u8);
        }
        Chunk {
            index: idx,
            data: (&out[..]).try_into().expect("should be exactly 32 bytes"),
        }
    }
}

#[hax_lib::attributes]
impl Encoder for PolyEncoder {
    fn encode_bytes(msg: &[u8]) -> Result<Self, super::EncodingError> {
        Self::encode_bytes_base(msg)
    }

    fn next_chunk(&mut self) -> Chunk {
        let out = self.chunk_at(self.idx as u16);
        self.idx = self.idx.wrapping_add(1);
        out
    }

    #[hax_lib::requires(false)]
    fn data(&self) -> &Vec<u8> {
        todo!()
    }
}

#[derive(Clone)]
pub struct PolyDecoder {
    // When using MLKEM-768 pts_needed <= 576
    pub pts_needed: usize,
    // polys == (size of an encoding chunk)/(size of a field element)
    //polys: usize,

    // A set of points ordered and equality-checked by the X value. When using
    // MLKEM-768, the size of the sorted set will not exceed
    // 2*MAX_STORED_POLYNOMIAL_DEGREE_V1 + 1
    //
    // It can get this large because when we will only add a new chunk if it has
    // index less than the degree of the polynomial plus 1 (to allow decoding
    // without interpolation) or if we do not have enough chunks yet. Thus it is
    // possible for us to receive MAX_STORED_POLYNOMIAL_DEGREE_V1 chunks with
    // index > MAX_STORED_POLYNOMIAL_DEGREE_V1+1 and also receive all
    // MAX_STORED_POLYNOMIAL_DEGREE_V1 + 1 chunks with index below
    // MAX_STORED_POLYNOMIAL_DEGREE_V1+1 before decoding the message.
    pts: [SortedSet<Pt>; 16],
    is_complete: bool,
}

#[hax_lib::attributes]
impl PolyDecoder {
    pub fn get_pts_needed(&self) -> usize {
        self.pts_needed
    }

    fn necessary_points(&self, poly: usize) -> usize {
        let points_per_poly = self.pts_needed / 16;
        let points_remaining = self.pts_needed % 16;
        if poly < points_remaining {
            points_per_poly + 1
        } else {
            points_per_poly
        }
    }

    fn new_with_poly_count(len_bytes: usize, _polys: usize) -> Result<Self, super::EncodingError> {
        if len_bytes % 2 != 0 {
            return Err(PolynomialError::MessageLengthEven.into());
        }
        Ok(Self {
            pts_needed: len_bytes / 2,
            pts: core::array::from_fn(|_| SortedSet::new()),
            is_complete: false,
        })
    }

    pub fn into_pb(self) -> proto::pq_ratchet::PolynomialDecoder {
        let mut out = proto::pq_ratchet::PolynomialDecoder {
            pts_needed: self.pts_needed as u32,
            polys: 16,
            is_complete: self.is_complete,
            pts: Vec::with_capacity(self.pts.len()),
        };
        for pts in self.pts.iter() {
            hax_lib::assume!(pts.len() <= 2 * MAX_STORED_POLYNOMIAL_DEGREE_V1 + 1);
            let mut v = Vec::<u8>::with_capacity(4 * pts.len());
            for i in 0..pts.len() {
                hax_lib::loop_invariant!(|i: usize| (v.len() == i * 4));
                let pt = &pts[i];
                v.extend_from_slice(&pt.serialize()[..]);
            }
            out.pts.push(v);
        }
        out
    }

    pub fn from_pb(pb: proto::pq_ratchet::PolynomialDecoder) -> Result<Self, PolynomialError> {
        if pb.pts.len() != 16 {
            return Err(PolynomialError::SerializationInvalid);
        }
        let mut out = Self {
            pts_needed: pb.pts_needed as usize,
            is_complete: pb.is_complete,
            pts: core::array::from_fn(|_| SortedSet::new()),
        };
        for i in 0..16 {
            let pts = &pb.pts[i];
            if pts.len() % 4 != 0 {
                return Err(PolynomialError::SerializationInvalid);
            }
            let mut v = SortedSet::with_capacity(pts.len() / 4);
            for pt in pts.chunks_exact(4) {
                v.push(Pt::deserialize(pt.try_into().unwrap()));
            }
            out.pts[i] = v;
        }
        Ok(out)
    }
}

#[hax_lib::attributes]
impl Decoder for PolyDecoder {
    fn new(len_bytes: usize) -> Result<Self, super::EncodingError> {
        Self::new_with_poly_count(len_bytes, 16)
    }

    #[hax_lib::requires(self.pts.len() == 16)]
    fn add_chunk(&mut self, chunk: &Chunk) {
        for i in 0usize..16 {
            hax_lib::loop_invariant!(|_: usize| self.pts.len() == 16);
            let total_idx = (chunk.index as usize) * 16 + i;
            let poly = total_idx % 16;
            let poly_idx = total_idx / 16;
            let x = GF16::new(poly_idx as u16);
            let y1 = chunk.data[i * 2] as u16;
            let y2 = chunk.data[i * 2 + 1] as u16;
            let y = GF16::new((y1 << 8) + y2);
            // Only add a point if it is needed or if it has a small index
            // so it may help us decode without interpolating
            if poly_idx < self.necessary_points(i)
                || self.pts[poly].len() < self.necessary_points(i)
            {
                // This will discard new points whose X value matches a previous
                // old point, since we've implemented equality for the Pt object
                // to only care about the X value.
                self.pts[poly].push(Pt { x, y });
            }
        }
    }

    #[hax_lib::requires(self.pts_needed < MAX_INTERMEDIATE_POLYNOMIAL_DEGREE_V1)]
    fn decoded_message(&self) -> Option<Vec<u8>> {
        if self.is_complete {
            return None;
        }
        let mut points_vecs = Vec::with_capacity(self.pts.len());
        for i in 0..(self.pts.len()) {
            let pts = &self.pts[i];
            if pts.len() < self.necessary_points(i) {
                return None;
            } else {
                points_vecs.push(&pts[..self.necessary_points(i)]);
            }
        }
        // We may or may not need these vectors of points (only if we need
        // to do a lagrange_interpolate call).  For now, we just create
        // them regardless.  However, we could optimize to lazily create them
        // only when it's proven necessary.
        let mut polys: [Option<Poly>; 16] = core::array::from_fn(|_| None);
        let mut out: Vec<u8> = Vec::with_capacity(self.pts_needed * 2);
        for i in 0..self.pts_needed {
            let poly = i % 16;
            let poly_idx = i / 16;
            let pt = Pt {
                x: GF16::new(poly_idx as u16),
                y: GF16::ZERO,
            };
            let y = if let Ok(i) = self.pts[poly].binary_search(&pt) {
                hax_lib::assume!(i < self.pts[poly].len()); // TODO Needs a postcondition on binary_search
                self.pts[poly][i].y
            } else {
                hax_lib::assume!(poly < polys.len());
                if polys[poly].is_none() {
                    hax_lib::assume!(poly < points_vecs.len());
                    hax_lib::assume!(
                        points_vecs[poly].len() <= MAX_INTERMEDIATE_POLYNOMIAL_DEGREE_V1
                    );
                    polys[poly] = Some(Poly::lagrange_interpolate(points_vecs[poly]));
                }
                polys[poly]
                    .as_ref()
                    .expect("already computed lazily")
                    .compute_at(pt.x)
            };
            out.push((y.value >> 8) as u8);
            out.push(y.value as u8);
        }
        Some(out)
    }

    fn is_complete(&self) -> bool {
        self.is_complete
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::RngCore;

    #[test]
    fn encode_and_decode_small() {
        let mut encoder = PolyEncoder::encode_bytes(b"abcdefghij").expect("should work");
        let mut decoder = PolyDecoder::new(10).expect("should work");
        decoder.add_chunk(&encoder.chunk_at(1));
        decoder.add_chunk(&encoder.chunk_at(2));
        let msg = decoder.decoded_message();
        assert_eq!(msg.expect("decode should succeed"), b"abcdefghij");
    }

    #[test]
    fn encode_and_decode_large() {
        let mut chunks = Vec::<Chunk>::new();
        // chunk 0 is missing
        let chunks_needed = 1088 / 32 + 1;

        // Provide a set of chunks, none of which contain the initial data.
        // This provides the worst-case scenario of both the encoder and decoder
        // needing to compute all actual data.
        {
            let mut encoder = PolyEncoder::encode_bytes(&[3u8; 1088]).expect("should work");
            for i in chunks_needed..chunks_needed * 2 + 1 {
                chunks.push(encoder.chunk_at(i));
            }
        }
        let mut decoder = PolyDecoder::new(1088).expect("should work");
        for chunk in chunks {
            decoder.add_chunk(&chunk);
            let msg = decoder.decoded_message();
            if let Some(m) = msg {
                assert_eq!(m, &[3u8; 1088]);
                return;
            }
        }
        panic!("should have already decoded by here");
    }

    #[test]
    fn poly_lagrange_interpolate() {
        let mut pts = Vec::<Pt>::new();
        let mut rng = rand::rng();
        for i in 0..30 {
            pts.push(Pt {
                x: GF16::new(i as u16),
                y: GF16::new(rng.next_u32() as u16),
            });
        }
        let p = Poly::lagrange_interpolate(&pts);
        for pt in pts.iter() {
            assert_eq!(pt.y, p.compute_at(pt.x));
        }
        let mut pts2 = Vec::<Pt>::new();
        for i in 0..30 {
            let x = GF16::new((i + 30) as u16);
            pts2.push(Pt {
                x,
                y: p.compute_at(x),
            });
        }
        let p2 = Poly::lagrange_interpolate(&pts2);
        for pt in pts.iter() {
            assert_eq!(pt.y, p2.compute_at(pt.x));
        }
    }

    #[test]
    fn point_serialize_deserialize() {
        let pt = Pt {
            x: GF16::new(0x1234),
            y: GF16::new(0x5678),
        };
        let s = pt.serialize();
        let pt2 = Pt::deserialize(s);
        assert_eq!(pt.x, pt2.x);
        assert_eq!(pt.y, pt2.y);
    }

    #[test]
    fn to_and_from_pb() {
        let chunks_needed = 1088 / 32;

        let mut encoder = PolyEncoder::encode_bytes(&[3u8; 1088]).expect("should work");
        let mut decoder = PolyDecoder::new(1088).expect("should work");

        // 2 chunks remain after this.
        for i in 2..chunks_needed {
            decoder.add_chunk(&encoder.chunk_at(i));
        }

        // Before receiving/processing remaining chunks, do a round-trip for
        // both encoder/decoder to/from protobuf.
        let mut encoder2 = PolyEncoder::from_pb(encoder.into_pb()).unwrap();
        let mut decoder2 = PolyDecoder::from_pb(decoder.into_pb()).unwrap();

        for i in 0..2 {
            decoder2.add_chunk(&encoder2.chunk_at(i + chunks_needed));
        }
        let m = decoder2.decoded_message().unwrap();
        assert_eq!(m, &[3u8; 1088]);
    }

    #[test]
    fn const_polys() {
        lagrange_polys_for_complete_points::<35>();
    }
}
