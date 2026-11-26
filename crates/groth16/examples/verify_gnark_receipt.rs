//! Independently verify the public receipt of a commitment-free BN254 Gnark batch.

use std::error::Error;
use std::io::Read;
use std::path::Path;

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::{PrimeField, Zero};
use ark_groth16::{Groth16, Proof, VerifyingKey, prepare_verifying_key};

type G1 = [String; 2];
type G2 = [String; 4];
type Receipt = ((G1, G2, G2, G2, [G1; 2]), Vec<(G1, G2, G1)>);
type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn canonical<F: PrimeField>(decimal: &str) -> Result<F> {
    if decimal.len() > 78 || decimal.is_empty() || !decimal.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid decimal field element".into());
    }
    let value: F = decimal.parse().map_err(|_| "field element out of range")?;
    if value.into_bigint().to_string() != decimal {
        return Err("noncanonical decimal field element".into());
    }
    Ok(value)
}

fn g1([x, y]: G1) -> Result<G1Affine> {
    let x = canonical::<Fq>(&x)?;
    let y = canonical::<Fq>(&y)?;
    if x.is_zero() && y.is_zero() {
        return Ok(G1Affine::identity());
    }
    let point = G1Affine::new_unchecked(x, y);
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err("invalid G1 point".into());
    }
    Ok(point)
}

fn g2([x0, x1, y0, y1]: G2) -> Result<G2Affine> {
    let x = Fq2::new(canonical(&x0)?, canonical(&x1)?);
    let y = Fq2::new(canonical(&y0)?, canonical(&y1)?);
    if x.is_zero() && y.is_zero() {
        return Ok(G2Affine::identity());
    }
    let point = G2Affine::new_unchecked(x, y);
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err("invalid G2 point".into());
    }
    Ok(point)
}

fn statement(path: &Path) -> Result<Fr> {
    let json: serde_json::Value = serde_json::from_reader(std::fs::File::open(path)?)?;
    canonical(json["public_hash"].as_str().ok_or("missing public hash")?)
}

fn verify(receipt: Receipt, expected: usize, valid: Fr, changed: Fr) -> Result<()> {
    let ((alpha, beta, gamma, delta, [constant, input]), proofs) = receipt;
    if expected == 0 || proofs.len() != expected || valid == changed {
        return Err("wrong proof count or identical statements".into());
    }
    let vk = prepare_verifying_key(&VerifyingKey::<Bn254> {
        alpha_g1: g1(alpha)?,
        beta_g2: g2(beta)?,
        gamma_g2: g2(gamma)?,
        delta_g2: g2(delta)?,
        gamma_abc_g1: vec![g1(constant)?, g1(input)?],
    });
    for (index, (a, b, c)) in proofs.into_iter().enumerate() {
        let proof = Proof {
            a: g1(a)?,
            b: g2(b)?,
            c: g1(c)?,
        };
        if !Groth16::<Bn254>::verify_proof(&vk, &proof, &[valid])?
            || Groth16::<Bn254>::verify_proof(&vk, &proof, &[changed])?
        {
            return Err(
                format!("proof {} failed its independent statement check", index + 1).into(),
            );
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let [receipt, valid, changed, count]: [String; 4] = std::env::args()
        .skip(1)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| "usage: verify_gnark_receipt RECEIPT PUBLIC ALTERED EXPECTED_COUNT")?;
    let count: usize = count.parse()?;
    let limit = (count as u64)
        .checked_mul(1024)
        .and_then(|n| n.checked_add(4096))
        .ok_or("invalid proof count")?;
    let file = std::fs::File::open(receipt)?;
    if file.metadata()?.len() > limit {
        return Err("oversized proof receipt".into());
    }
    verify(
        serde_json::from_reader(file.take(limit))?,
        count,
        statement(Path::new(&valid))?,
        statement(Path::new(&changed))?,
    )?;
    println!("Arkworks verified {count} Gnark proofs and rejected every altered statement");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::{AffineRepr, CurveGroup};

    fn g1_coordinates(point: G1Affine) -> G1 {
        [point.x.to_string(), point.y.to_string()]
    }

    fn g2_coordinates(point: G2Affine) -> G2 {
        [
            point.x.c0.to_string(),
            point.x.c1.to_string(),
            point.y.c0.to_string(),
            point.y.c1.to_string(),
        ]
    }

    #[test]
    fn receipt_requires_canonical_points_count_and_altered_statement() {
        let p = G1Affine::generator();
        let q = G2Affine::generator();
        let key = (
            g1_coordinates(p),
            g2_coordinates(q),
            g2_coordinates(q),
            g2_coordinates(q),
            [g1_coordinates(p), g1_coordinates(p)],
        );
        // Bilinearity gives 2*3 = 1*1 + (1+7)*1 + (-3)*1 for the fixture.
        let proof = (
            g1_coordinates(p.mul_bigint([2]).into_affine()),
            g2_coordinates(q.mul_bigint([3]).into_affine()),
            g1_coordinates(-p.mul_bigint([3]).into_affine()),
        );
        let valid = Fr::from(7);
        let changed = Fr::from(8);
        let receipt = (key, vec![proof]);
        verify(receipt.clone(), 1, valid, changed).unwrap();
        assert!(verify(receipt.clone(), 2, valid, changed).is_err());
        assert!(verify(receipt.clone(), 1, changed, valid).is_err());
        let mut swapped = receipt;
        swapped.1[0].1.swap(0, 1);
        assert!(verify(swapped, 1, valid, changed).is_err());
        assert!(canonical::<Fq>(&Fq::MODULUS.to_string()).is_err());
        assert!(canonical::<Fq>("01").is_err());
    }
}
