//! Compare the ordinary and shifted B2 implementations against Arkworks.

use std::path::Path;
use std::sync::atomic::Ordering::Relaxed;

use ark_bn254::G2Projective;
use ark_ec::VariableBaseMSM;
use xark_groth16::msm::{self, shifted::ShiftedBases};

pub(crate) fn run(args: &[String]) {
    let [xbc_path, pk_path, directory, options @ ..] = args else {
        panic!(
            "usage: bench_prove query-msm-b2-shifted <circuit.xbc> <reduced pk.bin> <statement-dir> [samples] [warmups]"
        );
    };
    let (samples, warmups) = super::counts(options).unwrap_or_else(|reason| panic!("{reason}"));
    assert!(
        !super::super::tracking(),
        "set BENCH_TIME=1 to time query MSMs"
    );
    let (pk, scalars) = super::load(xbc_path, pk_path, Path::new(directory));
    let bases = &pk.b_g2_query;
    let (table, prepare) = super::timed(|| ShiftedBases::new(bases));
    let table = table.unwrap_or_else(|reason| panic!("{reason}"));
    let expected = G2Projective::msm_bigint(bases, &scalars);
    let baseline = || super::timed(|| msm::msm::<G2Projective>(bases, &scalars));
    let shifted = || super::timed(|| table.msm(&scalars));
    let mut timings = Vec::with_capacity(samples);
    for iteration in 0..(warmups + samples) {
        let baseline_first = iteration % 2 == 0;
        let ((control, baseline_time), (candidate, shifted_time)) = if baseline_first {
            (baseline(), shifted())
        } else {
            let candidate = shifted();
            (baseline(), candidate)
        };
        for (arm, point) in [("baseline", control), ("shifted", candidate)] {
            assert!(
                msm::same_point(&point, &expected),
                "{arm} B2 query iteration {} disagrees with Arkworks",
                iteration + 1
            );
        }
        if iteration >= warmups {
            timings.push((baseline_first, baseline_time, shifted_time));
        }
    }
    println!(
        "query msm B2 shifted verified: terms={} threads={} samples={samples} warmups={warmups} xark_glv={} xark_batch_affine={} table_payload_bytes={} prepare_ns={}",
        scalars.len(),
        rayon::current_num_threads(),
        msm::GLV.load(Relaxed),
        msm::BATCH_AFFINE.load(Relaxed),
        table.payload_bytes(),
        prepare.as_nanos(),
    );
    for (index, (baseline_first, baseline, shifted)) in timings.into_iter().enumerate() {
        let first = if baseline_first {
            "baseline"
        } else {
            "shifted"
        };
        println!(
            "query msm B2 shifted: sample={} first={first} baseline_ns={} shifted_ns={}",
            index + 1,
            baseline.as_nanos(),
            shifted.as_nanos(),
        );
    }
}
