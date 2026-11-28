//! Matched-circuit benchmark export, adapted from the MIT-licensed Xark
//! iden3 exporter at zz-sol/xark commit 160ee0af97c434044961037886b445fc4aec6982.
//! Copyright (c) 2026 Blueshift Labs Limited. See the repository LICENSE.

use std::fs::{self, OpenOptions};
use std::io::{self, BufWriter, Seek, SeekFrom, Write};
use std::path::Path;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalSerialize;
use xark_groth16::{ConstraintSource, r1cs::RowChunk};

fn u32_le(out: &mut impl Write, value: u32) -> io::Result<()> {
    out.write_all(&value.to_le_bytes())
}

fn u64_le(out: &mut impl Write, value: u64) -> io::Result<()> {
    out.write_all(&value.to_le_bytes())
}

fn count(value: usize) -> io::Result<u32> {
    u32::try_from(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

fn field(out: &mut impl Write, value: &Fr) -> io::Result<()> {
    value
        .serialize_uncompressed(out)
        .map_err(|e| io::Error::other(e.to_string()))
}

fn header(out: &mut impl Write, magic: &[u8; 4], version: u32, sections: u32) -> io::Result<()> {
    out.write_all(magic)?;
    u32_le(out, version)?;
    u32_le(out, sections)
}

fn section(out: &mut impl Write, kind: u32, bytes: u64) -> io::Result<()> {
    u32_le(out, kind)?;
    u64_le(out, bytes)
}

fn modulus(out: &mut impl Write) -> io::Result<()> {
    u32_le(out, 32)?;
    out.write_all(&Fr::MODULUS.to_bytes_le())
}

fn output(path: &Path) -> io::Result<BufWriter<fs::File>> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(BufWriter::with_capacity(1 << 20, options.open(path)?))
}

pub fn write(directory: &Path, src: &dyn ConstraintSource, assignment: &[Fr]) -> io::Result<()> {
    let wires = count(src.layout().num_vars())?;
    let public = count(src.layout().num_instance())?;
    let rows = count(src.num_constraints())?;
    if public == 0
        || public > wires
        || count(assignment.len())? != wires
        || assignment.first() != Some(&Fr::from(1u64))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid assignment layout",
        ));
    }
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(directory)?;
    write_circuit(directory, src, wires, public - 1, rows)?;
    write_witness(directory, wires, assignment)
}

fn write_circuit(
    directory: &Path,
    src: &dyn ConstraintSource,
    wires: u32,
    public: u32,
    rows: u32,
) -> io::Result<()> {
    let mut out = output(&directory.join("circuit.r1cs"))?;
    header(&mut out, b"r1cs", 1, 3)?;
    section(&mut out, 1, 64)?;
    modulus(&mut out)?;
    u32_le(&mut out, wires)?;
    u32_le(&mut out, 0)?; // all public wires are recorded as inputs
    u32_le(&mut out, public)?;
    u32_le(&mut out, 0)?; // the layout does not separate private inputs and derived values
    u64_le(&mut out, u64::from(wires))?;
    u32_le(&mut out, rows)?;

    u32_le(&mut out, 2)?;
    let size_at = out.stream_position()?;
    u64_le(&mut out, 0)?;
    let mut chunk = RowChunk::default();
    for window in src.windows(1 << 16) {
        src.expand(&window, &mut chunk);
        for row in 0..chunk.rows() {
            for matrix in 0..3 {
                let (columns, coefficients) = chunk.terms(row, matrix);
                u32_le(&mut out, count(columns.len())?)?;
                for (&column, coefficient) in columns.iter().zip(coefficients) {
                    u32_le(&mut out, column)?;
                    field(&mut out, coefficient)?;
                }
            }
        }
    }
    let end = out.stream_position()?;
    out.seek(SeekFrom::Start(size_at))?;
    u64_le(&mut out, end - size_at - 8)?;
    out.seek(SeekFrom::Start(end))?;
    section(&mut out, 3, u64::from(wires) * 8)?;
    for wire in 0..u64::from(wires) {
        u64_le(&mut out, wire)?;
    }
    out.flush()
}

fn write_witness(directory: &Path, wires: u32, assignment: &[Fr]) -> io::Result<()> {
    let mut out = output(&directory.join("witness.wtns"))?;
    header(&mut out, b"wtns", 2, 2)?;
    section(&mut out, 1, 40)?;
    modulus(&mut out)?;
    u32_le(&mut out, wires)?;
    section(&mut out, 2, u64::from(wires) * 32)?;
    for value in assignment {
        field(&mut out, value)?;
    }
    out.flush()
}
