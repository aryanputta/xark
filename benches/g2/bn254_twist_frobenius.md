# Four-dimensional BN254 G2 scalar splitting

Let `u = 4965661367192848881`, `λ = p mod r = 6u²`, and `ψ` be the twist Frobenius. On the prime-order subgroup `ψ(P) = [λ]P`. The relation `ψ² = −φ` uses Arkworks' sparse cubic map `φ(x,y) = (ωx,y)`. The third image can be obtained by applying `ψ²` to `ψ(P)`. The scalar identities require subgroup membership. [Pinned Arkworks source](https://github.com/arkworks-rs/algebra/blob/bffa52711f225e888c1a91e1ec9fc59f2d9d5c94/curves/bn254/src/curves/g2.rs)

Reducing `1, λ, λ², λ³` modulo `r = 36u⁴ + 36u³ + 18u² + 6u + 1` gives the polynomial representatives

```text
1
6u²
−36u³ − 18u² − 6u − 1
−36u³ − 24u² − 12u − 3
```

The following rows have dot products `0, −2r, r, 2r` with those representatives, and the determinant of the row matrix is exactly `r`. The scalar map has image of size `r` because the first coefficient is `1`, so the rows span its full integer kernel.

```text
(2u,   u+1,  −u,   u)
(2u+1,   0,  2u,   1)
(u+1,    u,   u, −2u)
(2u+1,  −u, −u−1, −u)
```

Expand `(s,0,0,0)` in this row basis and round each rational coefficient to the nearest integer. The residual gives `s ≡ a₀ + λa₁ + λ²a₂ + λ³a₃ (mod r)`. Each rounding error has magnitude at most `1/2`, so coordinate `j` has bound `floor(sum_i |B[i,j]|/2)`. The exact bounds are `17379814785174971085`, `7448492050789273322`, `12414153417982122203`, and `9931322734385697762`, or at most `64, 63, 64, 64` magnitude bits.

## Public fixed shift used in table preparation

For `s = 2^128` the signed split is

```text
(6994998879106512636, -1489860392368150449, 1489860392368150451, -1489860392368150451)
```

The largest magnitude uses 63 bits. A joint binary accumulator initialized from the highest mask has 62 doublings, compared with 128 in the existing shifted-table preparation loop. The nonzero four-bit masks are `1, 12, 14, 15` and occur `20, 1, 13, 12` times. With sign-adjusted bases `Q0=P`, `Q1=−ψ(P)`, `Q2=ψ²(P)`, `Q3=−ψ³(P)`, prepare `Q12=Q2+Q3`, `Q14=Q1+Q12`, and `Q15=Q0+Q14`. This uses three subset additions and 45 accumulator additions after initialization. Basis generation takes two general `Fq2` products for `ψ(P)` and two base-field products each for `ψ²(P)` and `ψ³(P)`. Those are in addition to conjugations and sign negations.

The arithmetic model trades 66 doublings for 48 additions and the basis transforms. It excludes normalization, which the existing table amortizes across points via batch normalization. Setup time for this variant is unmeasured. [Current shifted preparation loop](https://github.com/aryanputta/xark/blob/730121d/crates/groth16/examples/support/shifted_b2.rs#L25-L43)

## Variable-scalar B2 depth and payload

Keeping Booth width 11 for comparison, the current 128-bit GLV bound needs 12 windows including carry. The four-dimensional 64-bit bound needs six. Each eligible input contributes four signed base/scalar pairs, compared with two under GLV. The rectangular digit work is `4 × 6 = 2 × 12 = 24` slots per eligible input. Actual nonzero count, affine routing, queue pressure and parallel scheduling are separate measurements.

The rows below count only affine coordinates at 128 bytes per G2 point. The four-image table includes the original image. The additional payload assumes the original point is already present. The last column compares transient affine point buffers for eligible entries only, using 4,282 withdrawal and 5,892 escrow entries from the recorded GLV class.

| Fixture | B2 terms | Current base payload | All four images | Additional three images | Eligible transient GLV → GLS |
| --- | ---: | ---: | ---: | ---: | ---: |
| Withdrawal | 5,406 | 691,968 B | 2,767,872 B | 2,075,904 B | 1,096,192 → 2,192,384 B |
| Escrow | 7,606 | 973,568 B | 3,894,272 B | 2,920,704 B | 1,508,352 → 3,016,704 B |

Retaining the existing 32-byte scalar and 4-byte index entries would add another 308,304 B for withdrawal and 424,224 B for escrow to the transient expansion. The coordinates, scalars and index figures exclude bucket scratch, allocation overhead and process RSS. An eager four-image cache is optional. `ψ²` and `ψ³` admit the sparse construction above. The eligible counts are half the 8,564 and 11,784 expanded entries in the verified `glv_split=true` occupancy rows at `0de2303`.

## Exact rounding without division for each scalar

Let `c` be a nonnegative cofactor magnitude and `K = floor(2^512 c/r)`. For a canonical scalar `s < r`, the error in replacing `sc/r` with `sK/2^512` is at most `s/2^512 < 1/(2r)` because `2r(r−1) < 2^512` for this modulus. Since `r` is odd, `sc/r` is at least `1/(2r)` from any half-integer. Both values round to exactly the same integer. The recoder can therefore compute `(sK + 2^511) >> 512` and then apply the constant cofactor sign.

This removes the division from each of the four runtime lattice coordinates. It uses a wider integer product. It needs separate timing and a limb-level implementation before any performance claim. The reference compares exact division and multiplication at the closest representable fractions on either side of every coefficient's half-integer boundary, plus 4,096 seeded canonical scalars.
