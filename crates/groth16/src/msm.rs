//! Multi-scalar multiplication (`Σ sᵢ·Pᵢ`).
//!
//! * [`naive_msm`] — textbook double-and-add over each scalar's integer bits. Slow,
//!   obviously correct, and convention-free: the independent oracle the fast path
//!   is tested against (alongside arkworks).
//! * [`msm`] — our Pippenger: scalars are partitioned by magnitude (zero / ±1 /
//!   ≤16 / ≤32 / ≤64 / ≤128 / full bits, using `r − s` for "small negative"
//!   values), and each class runs a signed-digit (Booth) bucket method with
//!   `2^(c−1)` buckets, parallel over `windows × point-slices`. Witness vectors are
//!   dominated by bits and small limbs, so most points never see a full-width scalar.
//! * [`StreamingMsm`] — the accumulator the prover folds chunk MSMs into. An MSM is
//!   an associative, commutative sum, so a vector split at *any* seams sums to the
//!   same point; the chunk is dropped as soon as it is folded.

use ark_bn254::Fr;
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use rayon::prelude::*;
use zeroize::Zeroizing;

#[cfg(feature = "msm-stage-profile-bench")]
mod stage_profile {
    use std::cell::RefCell;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant;

    thread_local! {
        static ACTIVE: RefCell<Option<Arc<Counters>>> = const { RefCell::new(None) };
    }
    static REQUEST: AtomicU64 = AtomicU64::new(0);

    #[derive(Default)]
    pub(super) struct Counters {
        pub classify_ns: AtomicU64,
        pub unit_ns: AtomicU64,
        pub glv_ns: AtomicU64,
        pub recode_ns: AtomicU64,
        pub gather_ns: AtomicU64,
        pub fill_ns: AtomicU64,
        pub flush_ns: AtomicU64,
        pub denominator_prefix_ns: AtomicU64,
        pub inversion_ns: AtomicU64,
        pub reverse_chain_ns: AtomicU64,
        pub point_update_ns: AtomicU64,
        pub reduce_ns: AtomicU64,
        pub merge_ns: AtomicU64,
        pub msm_ns: AtomicU64,
        pub msm_calls: AtomicU64,
        pub window_tasks: AtomicU64,
        pub nonempty_flushes: AtomicU64,
    }

    pub(super) fn current() -> Option<Arc<Counters>> {
        ACTIVE.with(|cell| cell.borrow().clone())
    }

    pub(super) fn add(slot: &AtomicU64, start: Instant) {
        slot.fetch_add(start.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }

    pub(super) fn next_request() -> u64 {
        REQUEST.fetch_add(1, Ordering::Relaxed)
    }

    struct Reset(Option<Arc<Counters>>);

    impl Drop for Reset {
        fn drop(&mut self) {
            ACTIVE.with(|cell| *cell.borrow_mut() = self.0.take());
        }
    }

    pub(super) fn task<T>(
        request: u64,
        label: &'static str,
        terms: usize,
        origin: Instant,
        f: impl FnOnce() -> T,
    ) -> T {
        // A separate opt-in marker keeps witness-derived timing and flush counts
        // out of ordinary application logs. Use synthetic inputs only.
        if std::env::var("XARK_MSM_STAGE_PROFILE").as_deref() != Ok("synthetic") {
            return f();
        }
        let counters = Arc::new(Counters::default());
        let previous = ACTIVE.with(|cell| cell.replace(Some(Arc::clone(&counters))));
        let reset = Reset(previous);
        let task_start_ns = origin.elapsed().as_nanos() as u64;
        let started = Instant::now();
        let value = f();
        let task_wall_ns = started.elapsed().as_nanos() as u64;
        let task_end_ns = origin.elapsed().as_nanos() as u64;
        drop(reset);
        let get = |slot: &AtomicU64| slot.load(Ordering::Relaxed);
        println!(
            "{{\"kind\":\"msm_stage\",\"request\":{request},\"task\":\"{label}\",\"terms\":{terms},\"rayon_threads\":{},\"task_start_ns\":{task_start_ns},\"task_end_ns\":{task_end_ns},\"task_wall_ns\":{task_wall_ns},\"msm_call_sum_ns\":{},\"classify_ns\":{},\"unit_ns\":{},\"glv_ns\":{},\"recode_ns\":{},\"gather_ns\":{},\"fill_task_sum_ns\":{},\"flush_nested_ns\":{},\"denominator_prefix_ns\":{},\"single_inversion_ns\":{},\"reverse_chain_ns\":{},\"point_update_ns\":{},\"reduce_task_sum_ns\":{},\"merge_ns\":{},\"msm_calls\":{},\"window_tasks\":{},\"nonempty_flushes\":{},\"overlapping_task_sums\":true}}",
            rayon::current_num_threads(),
            get(&counters.msm_ns),
            get(&counters.classify_ns),
            get(&counters.unit_ns),
            get(&counters.glv_ns),
            get(&counters.recode_ns),
            get(&counters.gather_ns),
            get(&counters.fill_ns),
            get(&counters.flush_ns),
            get(&counters.denominator_prefix_ns),
            get(&counters.inversion_ns),
            get(&counters.reverse_chain_ns),
            get(&counters.point_update_ns),
            get(&counters.reduce_ns),
            get(&counters.merge_ns),
            get(&counters.msm_calls),
            get(&counters.window_tasks),
            get(&counters.nonempty_flushes),
        );
        value
    }
}

/// One identifier shared by the B1 and B2 spans of a resident proof request.
#[doc(hidden)]
#[inline(always)]
pub fn next_bench_profile_request() -> u64 {
    #[cfg(feature = "msm-stage-profile-bench")]
    {
        stage_profile::next_request()
    }
    #[cfg(not(feature = "msm-stage-profile-bench"))]
    {
        0
    }
}

/// Profile only an explicitly marked synthetic B-query task.
#[doc(hidden)]
#[inline(always)]
pub fn bench_profile_task<T>(
    request: u64,
    label: &'static str,
    terms: usize,
    #[cfg(feature = "msm-stage-profile-bench")] origin: std::time::Instant,
    f: impl FnOnce() -> T,
) -> T {
    #[cfg(feature = "msm-stage-profile-bench")]
    {
        stage_profile::task(request, label, terms, origin, f)
    }
    #[cfg(not(feature = "msm-stage-profile-bench"))]
    {
        let _ = (request, label, terms);
        f()
    }
}

#[cfg(feature = "msm-g2-shifted-bench")]
#[doc(hidden)]
pub mod shifted;

/// A scalar in canonical (non-Montgomery) integer form.
pub type Scalar = <Fr as PrimeField>::BigInt;

/// Short-Weierstrass groups: affine coordinates for batch-affine accumulation.
pub trait SwCurve: CurveGroup<ScalarField = Fr, BaseField: crate::limbs::FastSub> {
    /// `(x, y)`, or `None` for the point at infinity.
    fn xy(a: &Self::Affine) -> Option<(Self::BaseField, Self::BaseField)>;
    /// The affine point `(x, y)` (on the curve by construction).
    fn from_xy(x: Self::BaseField, y: Self::BaseField) -> Self::Affine;
    /// The curve's `a` coefficient (for the doubling slope `(3x² + a)/2y`).
    fn coeff_a() -> Self::BaseField;
    /// The group's GLV decomposition, and its endomorphism `φ` on a point.
    fn glv() -> &'static crate::glv::Glv;
    fn endo(a: &Self::Affine) -> Self::Affine;

    #[cfg(feature = "msm-g2-endpoint-bench")]
    #[doc(hidden)]
    fn bench_sparse_endo(a: &Self::Affine) -> Self::Affine {
        Self::endo(a)
    }
}

impl<P> SwCurve for ark_ec::short_weierstrass::Projective<P>
where
    P: ark_ec::scalar_mul::glv::GLVConfig<ScalarField = Fr>,
    P::BaseField: crate::limbs::FastSub,
{
    #[inline(always)]
    fn xy(a: &Self::Affine) -> Option<(P::BaseField, P::BaseField)> {
        use ark_ec::AffineRepr;
        (!a.is_zero()).then_some((a.x, a.y))
    }
    #[inline(always)]
    fn from_xy(x: P::BaseField, y: P::BaseField) -> Self::Affine {
        ark_ec::short_weierstrass::Affine::new_unchecked(x, y)
    }
    fn coeff_a() -> P::BaseField {
        P::COEFF_A
    }
    fn glv() -> &'static crate::glv::Glv {
        use ark_ec::scalar_mul::glv::GLVConfig;
        if P::LAMBDA == ark_bn254::g1::Config::LAMBDA {
            crate::glv::g1()
        } else {
            assert!(
                P::LAMBDA == ark_bn254::g2::Config::LAMBDA,
                "not a BN254 group"
            );
            crate::glv::g2()
        }
    }
    #[inline(always)]
    fn endo(a: &Self::Affine) -> Self::Affine {
        P::endomorphism_affine(a)
    }

    #[cfg(feature = "msm-g2-endpoint-bench")]
    #[inline(always)]
    fn bench_sparse_endo(a: &Self::Affine) -> Self::Affine {
        use ark_ec::scalar_mul::glv::GLVConfig;

        if P::LAMBDA != ark_bn254::g2::Config::LAMBDA {
            return Self::endo(a);
        }
        let mut coefficients = P::ENDO_COEFFS[0].to_base_prime_field_elements();
        let real = coefficients.next().expect("endomorphism coefficient");
        assert!(coefficients.all(|coefficient| coefficient.is_zero()));
        let mut transformed = *a;
        transformed.x = transformed.x.mul_by_base_prime_field(&real);
        transformed
    }
}

/// Accumulate buckets in affine coordinates with batched inversions (default
/// on); a switch so `examples/bench_kernels.rs` and `bench_prove.rs` can compare
/// against XYZZ accumulation.
pub static BATCH_AFFINE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Split full-width scalars with the GLV endomorphism (default on); a switch so
/// `examples/bench_msm.rs` can compare.
pub static GLV: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Additions per shared inversion.
const BATCH: usize = 512;

#[cfg(feature = "msm-g2-endpoint-bench")]
static G2_TRIM_INVERSE_ENDPOINTS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "msm-g2-endpoint-bench")]
static G2_SPARSE_ENDOMORPHISM: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Toggle endpoint elision in G2 affine batch inversion before benchmarking.
#[cfg(feature = "msm-g2-endpoint-bench")]
#[doc(hidden)]
pub fn set_bench_g2_trim_inverse_endpoints(enabled: bool) {
    G2_TRIM_INVERSE_ENDPOINTS.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

/// Toggle the base-field specialization of the G2 GLV point map before benchmarking.
#[cfg(feature = "msm-g2-endpoint-bench")]
#[doc(hidden)]
pub fn set_bench_g2_sparse_endomorphism(enabled: bool) {
    G2_SPARSE_ENDOMORPHISM.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

/// Affine buckets filled by batch-affine additions: each `(bucket, point)` addition
/// costs ~5M+1S (vs 8M+2S for an XYZZ mixed add); one field inversion is shared
/// by a whole batch (Montgomery's trick). A bucket may appear once per batch; a
/// conflicting addition waits in a queue that is offered to the next batch. Only
/// if the queue stays full (skewed digits: a few hot buckets) does what is left
/// go to XYZZ side buckets, allocated then, so batches never stall.
struct AffineBuckets<G: SwCurve> {
    x: Vec<G::BaseField>,
    y: Vec<G::BaseField>,
    used: Vec<bool>,
    /// `stamp[b] == epoch` ⇔ bucket `b` is already in the current batch.
    stamp: Vec<u32>,
    epoch: u32,
    batch: Vec<(u32, G::BaseField, G::BaseField)>,
    queue: Vec<(u32, G::BaseField, G::BaseField)>,
    /// Empty until the queue first overflows.
    side: Vec<G::Bucket>,
    den: Vec<G::BaseField>,
    pre: Vec<G::BaseField>,
    #[cfg(feature = "msm-stage-profile-bench")]
    profile: Option<std::sync::Arc<stage_profile::Counters>>,
    #[cfg(feature = "msm-g2-endpoint-bench")]
    trim_inverse_endpoints: bool,
}

impl<G: SwCurve> AffineBuckets<G> {
    fn new(nb: usize) -> Self {
        AffineBuckets {
            x: vec![G::BaseField::zero(); nb],
            y: vec![G::BaseField::zero(); nb],
            used: vec![false; nb],
            stamp: vec![0; nb],
            epoch: 1,
            batch: Vec::with_capacity(BATCH),
            queue: Vec::with_capacity(BATCH),
            side: Vec::new(),
            den: Vec::with_capacity(BATCH),
            pre: Vec::with_capacity(BATCH),
            #[cfg(feature = "msm-stage-profile-bench")]
            profile: None,
            #[cfg(feature = "msm-g2-endpoint-bench")]
            trim_inverse_endpoints: G::BaseField::extension_degree() == 2
                && G2_TRIM_INVERSE_ENDPOINTS.load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    /// Add `(px, py)` to bucket `b` now, or batch it; `false` if the bucket is
    /// already in this batch.
    #[inline(always)]
    fn place(&mut self, b: u32, px: G::BaseField, py: G::BaseField) -> bool {
        let bi = b as usize;
        if !self.used[bi] {
            self.x[bi] = px;
            self.y[bi] = py;
            self.used[bi] = true;
        } else if self.stamp[bi] == self.epoch {
            return false;
        } else {
            self.stamp[bi] = self.epoch;
            self.batch.push((b, px, py));
            if self.batch.len() == BATCH {
                self.flush();
            }
        }
        true
    }

    #[inline(always)]
    fn add(&mut self, b: u32, px: G::BaseField, py: G::BaseField) {
        let epoch = self.epoch;
        if !self.place(b, px, py) {
            self.queue.push((b, px, py));
            if self.queue.len() == BATCH {
                self.flush();
                self.drain();
                if self.queue.len() > BATCH / 2 {
                    self.spill();
                }
            }
        } else if self.epoch != epoch {
            self.drain();
        }
    }

    /// Offer the queued additions to the current batch.
    fn drain(&mut self) {
        let mut q = std::mem::take(&mut self.queue);
        q.retain(|&(b, px, py)| !self.place(b, px, py));
        self.queue = q;
    }

    /// Add what is still queued to the XYZZ side buckets.
    fn spill(&mut self) {
        if self.side.is_empty() {
            self.side = vec![G::ZERO_BUCKET; self.x.len()];
        }
        for &(b, px, py) in &self.queue {
            self.side[b as usize] += &G::from_xy(px, py);
        }
        self.queue.clear();
    }

    fn flush(&mut self) {
        #[cfg(feature = "msm-stage-profile-bench")]
        let start = self.profile.as_ref().map(|_| std::time::Instant::now());
        #[cfg(feature = "msm-stage-profile-bench")]
        let nonempty = !self.batch.is_empty();
        #[cfg(feature = "msm-g2-endpoint-bench")]
        if self.trim_inverse_endpoints {
            self.invert_and_update::<true>();
        } else {
            self.invert_and_update::<false>();
        }
        #[cfg(not(feature = "msm-g2-endpoint-bench"))]
        self.invert_and_update::<false>();
        self.batch.clear();
        self.epoch = self.epoch.wrapping_add(1).max(1);
        #[cfg(feature = "msm-stage-profile-bench")]
        if let (Some(profile), Some(start)) = (&self.profile, start) {
            stage_profile::add(&profile.flush_ns, start);
            if nonempty {
                profile
                    .nonempty_flushes
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    #[inline]
    fn invert_and_update<const TRIM: bool>(&mut self) {
        use crate::limbs::FastSub;
        use ark_ff::AdditiveGroup;
        #[cfg(feature = "msm-stage-profile-bench")]
        let denominator_start = self.profile.as_ref().map(|_| std::time::Instant::now());
        self.den.clear();
        self.pre.clear();
        let denominator = |b: u32, px: G::BaseField, py: G::BaseField| {
            let (x1, y1) = (self.x[b as usize], self.y[b as usize]);
            if x1 != px {
                px.fsub(&x1)
            } else if y1 == py && !y1.is_zero() {
                y1.double() // doubling
            } else {
                G::BaseField::one() // P + (−P) = ∞: no inverse needed
            }
        };
        let mut acc = if TRIM {
            let Some(&(b, px, py)) = self.batch.first() else {
                return;
            };
            denominator(b, px, py)
        } else {
            G::BaseField::one()
        };
        let first = usize::from(TRIM);
        for &(b, px, py) in &self.batch[first..] {
            let d = denominator(b, px, py);
            self.pre.push(acc);
            self.den.push(d);
            acc *= d;
        }
        #[cfg(feature = "msm-stage-profile-bench")]
        if let (Some(profile), Some(start)) = (&self.profile, denominator_start) {
            stage_profile::add(&profile.denominator_prefix_ns, start);
        }
        #[cfg(feature = "msm-stage-profile-bench")]
        let inversion_start = self.profile.as_ref().map(|_| std::time::Instant::now());
        let mut inv = acc.inverse().expect("nonzero batch denominator");
        #[cfg(feature = "msm-stage-profile-bench")]
        if let (Some(profile), Some(start)) = (&self.profile, inversion_start) {
            stage_profile::add(&profile.inversion_ns, start);
        }
        #[cfg(feature = "msm-stage-profile-bench")]
        let enabled = self.profile.is_some();
        #[cfg(feature = "msm-stage-profile-bench")]
        let mut reverse_chain_ns = 0;
        #[cfg(feature = "msm-stage-profile-bench")]
        let mut point_update_ns = 0;
        for i in (0..self.den.len()).rev() {
            #[cfg(feature = "msm-stage-profile-bench")]
            let chain_start = enabled.then(std::time::Instant::now);
            let inv_i = inv * self.pre[i];
            inv *= self.den[i];
            #[cfg(feature = "msm-stage-profile-bench")]
            if let Some(start) = chain_start {
                reverse_chain_ns += start.elapsed().as_nanos() as u64;
            }
            #[cfg(feature = "msm-stage-profile-bench")]
            let update_start = enabled.then(std::time::Instant::now);
            self.apply_inverse(i + first, inv_i);
            #[cfg(feature = "msm-stage-profile-bench")]
            if let Some(start) = update_start {
                point_update_ns += start.elapsed().as_nanos() as u64;
            }
        }
        if TRIM {
            // The reverse sweep has multiplied out every factor except d₀.
            #[cfg(feature = "msm-stage-profile-bench")]
            let update_start = enabled.then(std::time::Instant::now);
            self.apply_inverse(0, inv);
            #[cfg(feature = "msm-stage-profile-bench")]
            if let Some(start) = update_start {
                point_update_ns += start.elapsed().as_nanos() as u64;
            }
        }
        #[cfg(feature = "msm-stage-profile-bench")]
        if let Some(profile) = &self.profile {
            profile
                .reverse_chain_ns
                .fetch_add(reverse_chain_ns, std::sync::atomic::Ordering::Relaxed);
            profile
                .point_update_ns
                .fetch_add(point_update_ns, std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[inline(always)]
    fn apply_inverse(&mut self, i: usize, inv: G::BaseField) {
        use crate::limbs::FastSub;
        use ark_ff::AdditiveGroup;
        let (b, px, py) = self.batch[i];
        let bi = b as usize;
        let (x1, y1) = (self.x[bi], self.y[bi]);
        let lambda = if x1 != px {
            py.fsub(&y1) * inv
        } else if y1 == py && !y1.is_zero() {
            (x1.square().double() + x1.square() + G::coeff_a()) * inv
        } else {
            self.used[bi] = false;
            return;
        };
        let x3 = lambda.square().fsub(&x1).fsub(&px);
        self.y[bi] = (lambda * x1.fsub(&x3)).fsub(&y1);
        self.x[bi] = x3;
    }

    /// Finish the batches (the queue's last few go to the side buckets); each
    /// bucket is its affine part plus its side sum, if any.
    #[allow(clippy::type_complexity)]
    fn finish(
        mut self,
    ) -> (
        Vec<G::BaseField>,
        Vec<G::BaseField>,
        Vec<bool>,
        Vec<G::Bucket>,
    ) {
        self.flush();
        for _ in 0..2 {
            if self.queue.is_empty() {
                break;
            }
            self.drain();
            self.flush();
        }
        if !self.queue.is_empty() {
            self.spill();
        }
        (self.x, self.y, self.used, self.side)
    }
}

/// Σ sᵢ·Pᵢ by plain double-and-add, MSB first, over all 256 bits of each scalar's
/// integer value. Pairs beyond the shorter input are ignored.
pub fn naive_msm<G: CurveGroup>(bases: &[G::Affine], scalars: &[Scalar]) -> G {
    let mut acc = G::zero();
    for (p, s) in bases.iter().zip(scalars) {
        let mut term = G::zero();
        for i in (0..256).rev() {
            term.double_in_place();
            if s.get_bit(i) {
                term += p;
            }
        }
        acc += term;
    }
    acc
}

/// Canonical (compressed affine) encoding of a point — compare points through
/// this, never through raw projective coordinates, which differ for equal points.
pub fn canonical_bytes<G: CurveGroup>(p: &G) -> Vec<u8> {
    let mut out = Vec::new();
    p.into_affine()
        .serialize_compressed(&mut out)
        .expect("serializing to a Vec cannot fail");
    out
}

/// Whether two group elements are the same point (compared in normalized form).
pub fn same_point<G: CurveGroup>(a: &G, b: &G) -> bool {
    canonical_bytes(a) == canonical_bytes(b)
}

/// Fold-as-you-go MSM: feed `(bases, scalars)` chunks in any order and at any
/// seams; [`finish`](Self::finish) returns the same point as one MSM over the
/// concatenation.
pub struct StreamingMsm<G: SwCurve> {
    acc: G,
    terms: usize,
}

impl<G: SwCurve> Default for StreamingMsm<G> {
    fn default() -> Self {
        Self::new()
    }
}

impl<G: SwCurve> StreamingMsm<G> {
    pub fn new() -> Self {
        Self {
            acc: G::zero(),
            terms: 0,
        }
    }

    /// Fold one chunk. Only `min(bases.len(), scalars.len())` pairs are used.
    pub fn feed(&mut self, bases: &[G::Affine], scalars: &[Scalar]) {
        self.acc += msm::<G>(bases, scalars);
        self.terms += bases.len().min(scalars.len());
    }

    /// Pairs folded so far.
    pub fn terms(&self) -> usize {
        self.terms
    }

    pub fn finish(self) -> G {
        self.acc
    }
}

/// Bits `[pos, pos+len)` of `s` (zero past bit 255). `len < 64`.
#[inline(always)]
fn bits_at(s: &Scalar, pos: usize, len: usize) -> u64 {
    let limbs = s.as_ref();
    let (q, r) = (pos / 64, pos % 64);
    if q >= limbs.len() {
        return 0;
    }
    let mut v = limbs[q] >> r;
    if r + len > 64 && q + 1 < limbs.len() {
        v |= limbs[q + 1] << (64 - r);
    }
    v & ((1u64 << len) - 1)
}

/// Booth (signed) digit `w` of width `c`: `v + b₋₁ − 2^c·b_top`, in
/// `[−2^(c−1), 2^(c−1)]`. Σ_w d_w·2^(wc) = s whenever the windows cover one bit
/// past the scalar's top bit.
#[inline(always)]
fn booth_digit(s: &Scalar, w: usize, c: usize) -> i64 {
    let pos = w * c;
    let v = bits_at(s, pos, c) as i64;
    let carry = if pos == 0 {
        0
    } else {
        bits_at(s, pos - 1, 1) as i64
    };
    v + carry - (((v >> (c - 1)) & 1) << c)
}

/// Window width for `n` points of `bits`-bit magnitude in a group whose base
/// field has extension degree `ext` (1 for G1, 2 for G2), from the cost model
/// `windows(c) · (n · add(c) + 0.8 · 2^c)` in mixed XYZZ additions, minimized
/// over `c ∈ [2, 15]` (≤ 15 keeps every signed digit in an `i16`). Unlike a
/// size-only `ln n` rule this shrinks the window for narrow scalars, where fewer
/// windows can't be bought back with more buckets. Where [`pippenger`]
/// accumulates batch-affine (`2^(c−1) ≥ 64` buckets, `n ≥ 4·2^(c−1)`) an
/// addition costs 0.6, plus its share of the batch's inversion (30 in G1, 10 in
/// G2, whose additions cost more and inversion barely more; a batch holds at most
/// one addition a bucket), plus 0.1 for the additions a full batch turns away
/// (from 256 buckets, fewer the more buckets there are). The constants are fitted
/// to `examples/bench_msm.rs` on one thread, 2^8–2^14 points of either group: the
/// model picks the fastest width at every size measured, where the previous one
/// (every addition a mixed one, reduction 1.4) was up to 17% slower.
fn window_bits(n: usize, bits: usize, ext: u64) -> usize {
    let inv = if ext == 1 { 30.0 } else { 10.0 };
    let cost = |c: usize| {
        let nb = 1usize << (c - 1);
        let add = if nb >= 64 && n >= 4 * nb {
            let turned_away = if nb >= 256 {
                0.1 * (BATCH as f64 / nb as f64).min(1.0)
            } else {
                0.0
            };
            0.6 + inv / nb.min(BATCH) as f64 + turned_away
        } else {
            1.0
        };
        (bits + 1).div_ceil(c) as f64 * (n as f64 * add + 0.8 * (1u64 << c) as f64)
    };
    (2..=15)
        .min_by(|&a, &b| cost(a).total_cmp(&cost(b)))
        .unwrap()
}

/// One magnitude class: entries packed as `index | NEG` (index < 2³¹).
const NEG: u32 = 1 << 31;

#[derive(Clone, Copy)]
struct DigitPtr(*mut i16);
unsafe impl Send for DigitPtr {}
unsafe impl Sync for DigitPtr {}
impl DigitPtr {
    /// Method access, so closures capture the `Sync` wrapper, not the raw field.
    #[inline(always)]
    fn get(self) -> *mut i16 {
        self.0
    }
}

/// Signed-digit Pippenger over `entries` (point index + sign), each of whose
/// magnitude fits in `bits` bits. Full-width scalars are first split with the
/// GLV endomorphism (`k·P = k₁·P + k₂·φ(P)`, halves of [`HALF_BITS`]): twice the
/// points over half the windows, so each window's fixed cost (its bucket
/// reduction, `c` doublings) is paid half as often.
///
/// [`HALF_BITS`]: crate::glv::HALF_BITS
fn pippenger<G: SwCurve>(
    bases: &[G::Affine],
    scalars: &[Scalar],
    entries: &[u32],
    bits: usize,
    #[cfg(feature = "msm-stage-profile-bench")] profile: Option<
        &std::sync::Arc<stage_profile::Counters>,
    >,
) -> G {
    // Fewer windows also means fewer tasks, and twice the points larger bucket
    // sweeps: measured (`examples/bench_msm.rs`), the split is 4–19% faster up
    // to 2^18 points on one thread and 2^12 on sixteen, 7–17% slower past 2^19
    // and 2^15. So it is taken while points × threads ≤ 2^18.
    if bits <= crate::glv::HALF_BITS
        || entries.is_empty()
        || entries.len() * rayon::current_num_threads() > 1 << 16
        || !GLV.load(std::sync::atomic::Ordering::Relaxed)
    {
        return pippenger_core(
            bases,
            scalars,
            entries,
            bits,
            false,
            #[cfg(feature = "msm-stage-profile-bench")]
            profile,
        );
    }
    #[cfg(feature = "msm-g2-endpoint-bench")]
    if G::BaseField::extension_degree() == 2
        && G2_SPARSE_ENDOMORPHISM.load(std::sync::atomic::Ordering::Relaxed)
    {
        return pippenger_glv::<G>(
            bases,
            scalars,
            entries,
            G::bench_sparse_endo,
            #[cfg(feature = "msm-stage-profile-bench")]
            profile,
        );
    }
    pippenger_glv::<G>(
        bases,
        scalars,
        entries,
        G::endo,
        #[cfg(feature = "msm-stage-profile-bench")]
        profile,
    )
}

fn pippenger_glv<G: SwCurve>(
    bases: &[G::Affine],
    scalars: &[Scalar],
    entries: &[u32],
    endomorphism: impl Fn(&G::Affine) -> G::Affine + Sync,
    #[cfg(feature = "msm-stage-profile-bench")] profile: Option<
        &std::sync::Arc<stage_profile::Counters>,
    >,
) -> G {
    #[cfg(feature = "msm-stage-profile-bench")]
    let start = profile.map(|_| std::time::Instant::now());
    let glv = G::glv();
    let modulus = Fr::MODULUS;
    let n = entries.len();
    let mut pts = vec![G::Affine::default(); 2 * n];
    // GLV components still encode request scalars after digit recoding.
    let mut sc = Zeroizing::new(vec![Scalar::default(); 2 * n]);
    pts.par_chunks_mut(2 * 1024)
        .zip(sc.par_chunks_mut(2 * 1024))
        .zip(entries.par_chunks(1024))
        .for_each(|((p, k), es)| {
            for (j, &e) in es.iter().enumerate() {
                // A class entry's sign only picked its magnitude: split s itself.
                let i = (e & !NEG) as usize;
                let mut s = scalars[i];
                while s >= modulus {
                    s.sub_with_borrow(&modulus);
                }
                let ((s1, k1), (s2, k2)) = glv.decompose(&s);
                let b = bases[i];
                let phi = endomorphism(&b);
                p[2 * j] = if s1 { b } else { -b };
                p[2 * j + 1] = if s2 { phi } else { -phi };
                k[2 * j] = k1;
                k[2 * j + 1] = k2;
            }
        });
    #[cfg(feature = "msm-stage-profile-bench")]
    if let (Some(profile), Some(start)) = (profile, start) {
        stage_profile::add(&profile.glv_ns, start);
    }
    let ids: Vec<u32> = (0..2 * n as u32).collect();
    pippenger_core(
        &pts,
        &sc,
        &ids,
        crate::glv::HALF_BITS,
        true,
        #[cfg(feature = "msm-stage-profile-bench")]
        profile,
    )
}

/// [`pippenger`] without the split. `identity`: `entries[k] == k`, so the points
/// are already contiguous and need no gather.
fn pippenger_core<G: SwCurve>(
    bases: &[G::Affine],
    scalars: &[Scalar],
    entries: &[u32],
    bits: usize,
    identity: bool,
    #[cfg(feature = "msm-stage-profile-bench")] profile: Option<
        &std::sync::Arc<stage_profile::Counters>,
    >,
) -> G {
    let n = entries.len();
    if n == 0 {
        return G::zero();
    }
    // ≤ 15-bit windows so every signed digit (|d| ≤ 2^(c−1)) fits an i16.
    let c = window_bits(n, bits, G::BaseField::extension_degree());
    let windows = (bits + 1).div_ceil(c);
    let threads = rayon::current_num_threads().max(1);
    // Split points so `windows × parts` covers the pool ~2× over, but keep slices
    // large enough that the per-task bucket reduction (2^c adds) stays amortized.
    let parts = (2 * threads)
        .div_ceil(windows)
        .min((n >> (c + 1)).max(1))
        .max(1);
    let part_len = n.div_ceil(parts);
    let modulus = Fr::MODULUS;

    // Signed digits, computed once, stored window-major (each window pass then
    // streams one contiguous i16 row) with the entry's sign folded in.
    // Booth digits encode request scalars. Wipe them on return and unwinding.
    #[cfg(feature = "msm-stage-profile-bench")]
    let recode_start = profile.map(|_| std::time::Instant::now());
    let mut digits = Zeroizing::new(vec![0i16; windows * n]);
    {
        let ptr = DigitPtr(digits.as_mut_ptr());
        entries.par_chunks(4096).enumerate().for_each(|(ci, es)| {
            for (j, &e) in es.iter().enumerate() {
                let k = ci * 4096 + j;
                let s = scalars[(e & !NEG) as usize];
                let (m, neg) = if e & NEG != 0 {
                    let mut m = modulus;
                    m.sub_with_borrow(&s);
                    (m, true)
                } else {
                    (s, false)
                };
                for w in 0..windows {
                    let d = booth_digit(&m, w, c) as i16;
                    // SAFETY: (w, k) is written by exactly this task.
                    unsafe { *ptr.get().add(w * n + k) = if neg { -d } else { d } };
                }
            }
        });
    }
    #[cfg(feature = "msm-stage-profile-bench")]
    if let (Some(profile), Some(start)) = (profile, recode_start) {
        stage_profile::add(&profile.recode_ns, start);
    }

    // With several windows, gather this class's points contiguously once so every
    // window pass streams them sequentially instead of striding the shared array.
    #[cfg(feature = "msm-stage-profile-bench")]
    let gather_start = profile.map(|_| std::time::Instant::now());
    let gathered: Option<Vec<G::Affine>> = (windows > 1 && !identity).then(|| {
        entries
            .par_iter()
            .with_min_len(4096)
            .map(|&e| bases[(e & !NEG) as usize])
            .collect()
    });
    #[cfg(feature = "msm-stage-profile-bench")]
    if let (Some(profile), Some(start)) = (profile, gather_start) {
        stage_profile::add(&profile.gather_ns, start);
    }

    let sums: Vec<G> = (0..windows * parts)
        .into_par_iter()
        .map(|t| {
            #[cfg(feature = "msm-stage-profile-bench")]
            let fill_start = profile.map(|_| std::time::Instant::now());
            #[cfg(feature = "msm-stage-profile-bench")]
            if let Some(profile) = profile {
                profile
                    .window_tasks
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            let (w, part) = (t / parts, t % parts);
            let lo = part * part_len;
            let hi = n.min(lo + part_len);
            let row = &digits[w * n..(w + 1) * n];
            let base_of = |k: usize| -> &G::Affine {
                match &gathered {
                    Some(g) => &g[k],
                    None => &bases[(entries[k] & !NEG) as usize],
                }
            };
            let nb = 1usize << (c - 1);
            // Batch-affine pays off once a task has many points per bucket, and
            // enough buckets that a batch (one per bucket at most) shares its
            // inversion widely: with 32, it is 3.7× slower at 64 points.
            if BATCH_AFFINE.load(std::sync::atomic::Ordering::Relaxed)
                && nb >= 64
                && hi - lo >= 4 * nb
            {
                let mut ab = AffineBuckets::<G>::new(nb);
                #[cfg(feature = "msm-stage-profile-bench")]
                {
                    ab.profile = profile.cloned();
                }
                for (k, &d) in row.iter().enumerate().take(hi).skip(lo) {
                    if d == 0 {
                        continue;
                    }
                    let p = base_of(k);
                    if let Some((x, y)) = G::xy(p) {
                        ab.add((d.unsigned_abs() - 1) as u32, x, if d < 0 { -y } else { y });
                    }
                }
                let (bx, by, used, side) = ab.finish();
                #[cfg(feature = "msm-stage-profile-bench")]
                if let (Some(profile), Some(start)) = (profile, fill_start) {
                    stage_profile::add(&profile.fill_ns, start);
                }
                #[cfg(feature = "msm-stage-profile-bench")]
                let reduce_start = profile.map(|_| std::time::Instant::now());
                let mut running = G::ZERO_BUCKET;
                let mut res = G::ZERO_BUCKET;
                for j in (0..nb).rev() {
                    if used[j] {
                        running += &G::from_xy(bx[j], by[j]);
                    }
                    if let Some(b) = side.get(j) {
                        running += b;
                    }
                    res += &running;
                }
                #[cfg(feature = "msm-stage-profile-bench")]
                if let (Some(profile), Some(start)) = (profile, reduce_start) {
                    stage_profile::add(&profile.reduce_ns, start);
                }
                return res.into();
            }
            // Buckets in the curve's MSM bucket representation (XYZZ for short
            // Weierstrass: cheaper mixed additions than Jacobian).
            let mut buckets = vec![G::ZERO_BUCKET; nb];
            for k in lo..hi {
                let d = row[k];
                if d == 0 {
                    continue;
                }
                let base = match &gathered {
                    Some(g) => &g[k],
                    None => &bases[(entries[k] & !NEG) as usize],
                };
                let bucket = &mut buckets[(d.unsigned_abs() - 1) as usize];
                if d < 0 {
                    *bucket -= base;
                } else {
                    *bucket += base;
                }
            }
            #[cfg(feature = "msm-stage-profile-bench")]
            if let (Some(profile), Some(start)) = (profile, fill_start) {
                stage_profile::add(&profile.fill_ns, start);
            }
            #[cfg(feature = "msm-stage-profile-bench")]
            let reduce_start = profile.map(|_| std::time::Instant::now());
            // Σ_j (j+1)·bucket[j] via the running-sum trick (2·2^(c−1) adds).
            let mut running = G::ZERO_BUCKET;
            let mut res = G::ZERO_BUCKET;
            for b in buckets.iter().rev() {
                running += b;
                res += &running;
            }
            #[cfg(feature = "msm-stage-profile-bench")]
            if let (Some(profile), Some(start)) = (profile, reduce_start) {
                stage_profile::add(&profile.reduce_ns, start);
            }
            res.into()
        })
        .collect();

    #[cfg(feature = "msm-stage-profile-bench")]
    let merge_start = profile.map(|_| std::time::Instant::now());
    let mut total = G::zero();
    for w in (0..windows).rev() {
        for _ in 0..c {
            total.double_in_place();
        }
        for part in 0..parts {
            total += sums[w * parts + part];
        }
    }
    #[cfg(feature = "msm-stage-profile-bench")]
    if let (Some(profile), Some(start)) = (profile, merge_start) {
        stage_profile::add(&profile.merge_ns, start);
    }
    total
}

/// Magnitude classes (upper bit bounds); class 0 is `±1`.
const CLASS_BITS: [usize; 6] = [1, 16, 32, 64, 128, 256];

/// `Σ sᵢ·Pᵢ` over the first `min(bases.len(), scalars.len())` pairs. Scalars are
/// arbitrary 256-bit integers (values ≥ r are handled, e.g. `r·P = O`).
pub fn msm<G: SwCurve>(bases: &[G::Affine], scalars: &[Scalar]) -> G {
    #[cfg(feature = "msm-stage-profile-bench")]
    let profile = stage_profile::current();
    #[cfg(feature = "msm-stage-profile-bench")]
    let msm_start = profile.as_ref().map(|_| std::time::Instant::now());
    #[cfg(feature = "msm-stage-profile-bench")]
    if let Some(profile) = &profile {
        profile
            .msm_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    let n = bases.len().min(scalars.len());
    let (bases, scalars) = (&bases[..n], &scalars[..n]);
    assert!(n < NEG as usize, "MSM chunk too large");
    let modulus = Fr::MODULUS;

    // Partition by magnitude: each entry goes to the class of min(|s|, |r−s|).
    // A point at infinity (a variable absent from the key's matrix) adds nothing.
    let classify = |i: usize| -> Option<(usize, u32)> {
        let s = &scalars[i];
        if s.is_zero() || G::xy(&bases[i]).is_none() {
            return None;
        }
        let pos_bits = s.num_bits() as usize;
        let (bits, neg) = if pos_bits > 128 && *s < modulus {
            let mut m = modulus;
            m.sub_with_borrow(s);
            let nb = m.num_bits() as usize;
            if nb < pos_bits {
                (nb, true)
            } else {
                (pos_bits, false)
            }
        } else {
            (pos_bits, false)
        };
        if bits == 0 {
            // s == r (≡ 0): contributes nothing.
            return None;
        }
        let class = CLASS_BITS.iter().position(|&b| bits <= b).unwrap();
        Some((class, i as u32 | if neg { NEG } else { 0 }))
    };
    // Each task takes thousands of scalars: a few hundred would wake the whole
    // pool for microseconds of work.
    // Entries carry witness-dependent magnitude classes and signs. Keep the
    // buffers request-local and clear them when MSM accumulation finishes.
    #[cfg(feature = "msm-stage-profile-bench")]
    let classify_start = profile.as_ref().map(|_| std::time::Instant::now());
    let classes: Zeroizing<[Vec<u32>; 6]> = (0..n)
        .into_par_iter()
        .with_min_len(4096)
        .fold(
            || Zeroizing::new(std::array::from_fn(|_| Vec::new())),
            |mut acc: Zeroizing<[Vec<u32>; 6]>, i| {
                if let Some((c, e)) = classify(i) {
                    acc[c].push(e);
                }
                acc
            },
        )
        .reduce(
            || Zeroizing::new(std::array::from_fn(|_| Vec::new())),
            |mut a, b| {
                // Copy before b's guard clears its old allocation. Moving a
                // Vec would deallocate that allocation without wiping it.
                for (x, y) in a.iter_mut().zip(b.iter()) {
                    x.extend_from_slice(y);
                }
                a
            },
        );
    #[cfg(feature = "msm-stage-profile-bench")]
    if let (Some(profile), Some(start)) = (&profile, classify_start) {
        stage_profile::add(&profile.classify_ns, start);
    }

    // ±1: plain (signed) additions.
    #[cfg(feature = "msm-stage-profile-bench")]
    let unit_start = profile.as_ref().map(|_| std::time::Instant::now());
    let unit: G = classes[0]
        .par_chunks(4096)
        .map(|es| {
            let mut acc = G::ZERO_BUCKET;
            for &e in es {
                let p = &bases[(e & !NEG) as usize];
                if e & NEG != 0 {
                    acc -= p;
                } else {
                    acc += p;
                }
            }
            acc.into()
        })
        .sum();
    #[cfg(feature = "msm-stage-profile-bench")]
    if let (Some(profile), Some(start)) = (&profile, unit_start) {
        stage_profile::add(&profile.unit_ns, start);
    }
    let mut total = unit;
    for (class, entries) in classes.iter().enumerate().skip(1) {
        total += pippenger::<G>(
            bases,
            scalars,
            entries,
            CLASS_BITS[class],
            #[cfg(feature = "msm-stage-profile-bench")]
            profile.as_ref(),
        );
    }
    #[cfg(feature = "msm-stage-profile-bench")]
    if let (Some(profile), Some(start)) = (&profile, msm_start) {
        stage_profile::add(&profile.msm_ns, start);
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    #[cfg(feature = "msm-g2-endpoint-bench")]
    #[test]
    fn sparse_endomorphism_matches_arkworks_for_g2_and_leaves_g1_unchanged() {
        use ark_bn254::{G1Affine, G1Projective, G2Affine, G2Projective};
        use ark_ec::AffineRepr;

        for scalar in [0, 1, 2, 17, u64::MAX] {
            let g2 = G2Affine::generator().mul_bigint([scalar]).into_affine();
            let g1 = G1Affine::generator().mul_bigint([scalar]).into_affine();
            assert_eq!(
                G2Projective::bench_sparse_endo(&g2),
                G2Projective::endo(&g2)
            );
            assert_eq!(
                G1Projective::bench_sparse_endo(&g1),
                G1Projective::endo(&g1)
            );
        }
    }

    #[cfg(feature = "msm-g2-endpoint-bench")]
    #[test]
    fn g2_inverse_endpoints_match_arkworks_across_batch_sizes() {
        use ark_bn254::{G2Affine, G2Projective};
        use ark_ec::AffineRepr;

        let p = G2Affine::generator();
        let q = (p.into_group() + p).into_affine();
        let points = [q, p, -p];
        for count in [0, 1, 2, 3, 511, 512] {
            for phase in 0..3 {
                for trim in [false, true] {
                    let mut buckets = AffineBuckets::<G2Projective>::new(count.max(1));
                    buckets.trim_inverse_endpoints = trim;
                    for b in 0..count {
                        let (x, y) = p.xy().unwrap();
                        buckets.add(b as u32, x, y);
                    }
                    for b in 0..count {
                        let (x, y) = points[(b + phase) % 3].xy().unwrap();
                        buckets.add(b as u32, x, y);
                    }
                    let epoch = buckets.epoch;
                    buckets.flush();
                    assert_eq!(buckets.epoch, epoch + 1);
                    if count < BATCH {
                        assert_eq!(buckets.pre.len(), count.saturating_sub(usize::from(trim)));
                        assert_eq!(buckets.den.len(), buckets.pre.len());
                    }
                    let (xs, ys, used, side) = buckets.finish();
                    assert!(side.is_empty());
                    for b in 0..count {
                        let expected = p.into_group() + points[(b + phase) % 3];
                        let actual = if used[b] {
                            G2Projective::from_xy(xs[b], ys[b]).into_group()
                        } else {
                            G2Projective::zero()
                        };
                        assert!(
                            same_point(&actual, &expected),
                            "count={count}, phase={phase}, bucket={b}, trim={trim}"
                        );
                    }
                }
            }
        }
    }

    #[cfg(feature = "msm-g2-endpoint-bench")]
    #[test]
    fn g2_inverse_endpoints_preserve_spills_and_cancelled_bucket_reuse() {
        use ark_bn254::{G2Affine, G2Projective};
        use ark_ec::AffineRepr;

        let p = G2Affine::generator();
        let q = (p.into_group() + p).into_affine();
        let mut additions = vec![(0, p), (0, -p), (1, p), (1, q)];
        additions.extend(std::iter::repeat_n((2, p), BATCH + 2));
        additions.push((0, q));
        additions.extend(std::iter::repeat_n((3, p), 8));
        let mut expected = [G2Projective::zero(); 4];
        for &(bucket, point) in &additions {
            expected[bucket as usize] += point;
        }
        for trim in [false, true] {
            let mut buckets = AffineBuckets::<G2Projective>::new(expected.len());
            buckets.trim_inverse_endpoints = trim;
            for &(bucket, point) in &additions {
                let (x, y) = point.xy().unwrap();
                buckets.add(bucket, x, y);
            }
            let (xs, ys, used, side) = buckets.finish();
            assert!(!side[2].is_zero());
            assert!(!side[3].is_zero());
            for (b, expected) in expected.iter().enumerate() {
                let mut actual: G2Projective = side[b].into();
                if used[b] {
                    actual += G2Projective::from_xy(xs[b], ys[b]);
                }
                assert!(same_point(&actual, expected), "bucket={b}, trim={trim}");
            }
        }
    }

    #[test]
    fn booth_digits_reconstruct_scalar() {
        use ark_ff::UniformRand;
        let mut rng = rand::thread_rng();
        for c in [3usize, 7, 11, 16] {
            for _ in 0..50 {
                let s = Fr::rand(&mut rng).into_bigint();
                let windows = 257usize.div_ceil(c);
                // Σ d_w 2^(wc) mod r == s.
                let mut acc = Fr::zero();
                let two_c = Fr::from(1u64 << c);
                for w in (0..windows).rev() {
                    acc *= two_c;
                    let d = booth_digit(&s, w, c);
                    assert!(d.unsigned_abs() <= 1 << (c - 1));
                    acc += if d < 0 {
                        -Fr::from(d.unsigned_abs())
                    } else {
                        Fr::from(d as u64)
                    };
                }
                assert_eq!(acc.into_bigint(), s);
            }
        }
    }
}
