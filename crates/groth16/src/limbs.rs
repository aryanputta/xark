//! Field addition and subtraction on Montgomery limbs, for the hot loops.
//!
//! arkworks' `+` and `−` on a 4-limb field compare the result against the
//! modulus limb by limb; these share the loads, reduce with one branch-free
//! select, and leave the result canonical, so they give the same elements.
//! Measured on Apple M3: `Fq` subtraction 2.7 ns in arkworks; the FFT butterfly
//! went from 17.6 to 12.0 ns with them.

use ark_bn254::Fq2;
use ark_ff::{BigInt, Field, Fp, FpConfig, PrimeField};

/// `a + b mod p`, for canonical `a, b < p < 2^255`.
#[inline(always)]
pub fn add(a: &[u64; 4], b: &[u64; 4], p: &[u64; 4]) -> [u64; 4] {
    let mut sum = [0u64; 4];
    let mut carry = 0u64;
    for i in 0..4 {
        let (x, c1) = a[i].overflowing_add(b[i]);
        let (x, c2) = x.overflowing_add(carry);
        sum[i] = x;
        carry = (c1 | c2) as u64;
    }
    let mut red = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (x, b1) = sum[i].overflowing_sub(p[i]);
        let (x, b2) = x.overflowing_sub(borrow);
        red[i] = x;
        borrow = (b1 | b2) as u64;
    }
    // sum < p exactly when sum − p borrows.
    let keep = 0u64.wrapping_sub(borrow);
    let mut out = [0u64; 4];
    for i in 0..4 {
        out[i] = (sum[i] & keep) | (red[i] & !keep);
    }
    out
}

/// `a − b mod p`, for canonical `a, b < p`.
#[inline(always)]
pub fn sub(a: &[u64; 4], b: &[u64; 4], p: &[u64; 4]) -> [u64; 4] {
    let mut diff = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (x, b1) = a[i].overflowing_sub(b[i]);
        let (x, b2) = x.overflowing_sub(borrow);
        diff[i] = x;
        borrow = (b1 | b2) as u64;
    }
    // a − b < 0: add p back.
    let add = 0u64.wrapping_sub(borrow);
    let mut carry = 0u64;
    for i in 0..4 {
        let (x, c1) = diff[i].overflowing_add(p[i] & add);
        let (x, c2) = x.overflowing_add(carry);
        diff[i] = x;
        carry = (c1 | c2) as u64;
    }
    diff
}

/// Fast subtraction for an MSM's base field.
pub trait FastSub: Sized {
    fn fsub(&self, b: &Self) -> Self;

    /// Visit inverses of nonzero denominators in reverse order, reusing scratch.
    #[doc(hidden)]
    fn batch_inverses(denominators: &[Self], scratch: &mut Vec<Self>, emit: impl FnMut(usize, Self))
    where
        Self: Field,
    {
        batch_inverses_in(
            denominators,
            scratch,
            |d| *d,
            |_, prefix| prefix,
            |d, prefix| (*d, *prefix),
            |_, inverse| inverse,
            emit,
        );
    }
}

/// The same Montgomery batch-inversion chain for a field and its projection.
fn batch_inverses_in<F, P: Field, S>(
    denominators: &[F],
    scratch: &mut Vec<S>,
    project: impl Fn(&F) -> P,
    save: impl Fn(P, P) -> S,
    recover: impl Fn(&F, &S) -> (P, P),
    lift: impl Fn(&F, P) -> F,
    mut emit: impl FnMut(usize, F),
) {
    scratch.clear();
    let mut product = P::one();
    for denominator in denominators {
        let projected = project(denominator);
        scratch.push(save(projected, product));
        product *= projected;
    }
    let mut inverse = product.inverse().expect("nonzero batch denominator");
    for (i, (denominator, saved)) in denominators.iter().zip(scratch.iter()).enumerate().rev() {
        let (projected, prefix) = recover(denominator, saved);
        let inverse_i = inverse * prefix;
        inverse *= projected;
        emit(i, lift(denominator, inverse_i));
    }
}

impl<P: FpConfig<4>> FastSub for Fp<P, 4> {
    #[inline(always)]
    fn fsub(&self, b: &Self) -> Self {
        let m = <Self as PrimeField>::MODULUS.0;
        Fp(
            BigInt(sub(&self.0.0, &b.0.0, &m)),
            core::marker::PhantomData,
        )
    }
}

impl FastSub for Fq2 {
    #[inline(always)]
    fn fsub(&self, b: &Self) -> Self {
        Fq2::new(self.c0.fsub(&b.c0), self.c1.fsub(&b.c1))
    }

    fn batch_inverses(
        denominators: &[Self],
        scratch: &mut Vec<Self>,
        emit: impl FnMut(usize, Self),
    ) {
        // In BN254, i² = −1. Invert the norms a² + b² in Fq, then multiply
        // the conjugates by those inverses. Each scratch slot holds the norm
        // and its prefix product as two Fq values.
        batch_inverses_in(
            denominators,
            scratch,
            |d| d.c0.square() + d.c1.square(),
            Self::new,
            |_, saved| (saved.c0, saved.c1),
            |d, inverse| Self::new(d.c0 * inverse, -(d.c1 * inverse)),
            emit,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fq;
    use ark_ff::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn check_inverses<F: FastSub + Field>(values: &[F]) {
        let mut scratch = Vec::with_capacity(values.len());
        let capacity = scratch.capacity();
        for n in [0, 1, 2, 5, 511, 512, 5, 0] {
            let mut remaining = n;
            F::batch_inverses(&values[..n], &mut scratch, |i, inverse| {
                remaining -= 1;
                assert_eq!(i, remaining);
                assert_eq!(Some(inverse), values[i].inverse());
            });
            assert_eq!(remaining, 0);
            assert_eq!(scratch.len(), n);
            assert_eq!(scratch.capacity(), capacity);
        }
    }

    #[test]
    fn batch_inverses_match_arkworks_in_both_fields() {
        let mut rng = ChaCha20Rng::seed_from_u64(0);
        let one = Fq::from(1u64);
        let zero = Fq::from(0u64);
        let mut base = vec![one, -one];
        let mut ext = vec![
            Fq2::new(one, zero),
            Fq2::new(-one, zero),
            Fq2::new(zero, one),
            Fq2::new(zero, -one),
            Fq2::new(-one, one),
        ];
        base.resize_with(512, || Fq::rand(&mut rng));
        ext.resize_with(512, || Fq2::rand(&mut rng));
        check_inverses(&base);
        check_inverses(&ext);
    }
}
