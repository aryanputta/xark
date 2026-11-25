// Matched Privacy Rings runner. The iden3 reader below is from the
// MIT-licensed Xark benchmark at zz-sol/xark commit
// 160ee0af97c434044961037886b445fc4aec6982.
// Copyright (c) 2026 Blueshift Labs Limited. See the repository LICENSE.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/logger"
)

func main() {
	logger.Disable()
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "iden3-gnark:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 7 {
		return fmt.Errorf("usage: privacy-rings-gnark <r1cs> <wtns> <public.json> <public-changed.json> <threads> <runs> <warmups>")
	}
	numbers := make([]int, 3)
	for i, arg := range args[4:] {
		value, err := strconv.Atoi(arg)
		if err != nil || value < 1 {
			return fmt.Errorf("threads, runs and warmups must be positive integers")
		}
		numbers[i] = value
	}
	runtime.GOMAXPROCS(numbers[0])
	ccs, err := readR1CS(args[0])
	if err != nil {
		return err
	}
	publicCount := ccs.GetNbPublicVariables() - 1
	if publicCount != 1 {
		return fmt.Errorf("expected one public input, got %d", publicCount)
	}
	w, err := readWitness(args[1], publicCount, ccs.GetNbSecretVariables())
	if err != nil {
		return err
	}
	expected, err := readStatement(args[2])
	if err != nil {
		return err
	}
	changed, err := readStatement(args[3])
	if err != nil {
		return err
	}
	if expected.Cmp(changed) == 0 {
		return fmt.Errorf("changed statement must differ")
	}
	public, err := w.Public()
	if err != nil {
		return err
	}
	actual, ok := public.Vector().(fr.Vector)
	var expectedField fr.Element
	expectedField.SetBigInt(expected)
	if !ok || len(actual) != 1 || !actual[0].Equal(&expectedField) {
		return fmt.Errorf("witness does not match the fixture public statement")
	}
	invalid, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	values := make(chan any, 1)
	values <- changed
	close(values)
	if err := invalid.Fill(1, 0, values); err != nil {
		return err
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return fmt.Errorf("setup: %w", err)
	}
	for i := 0; i < numbers[2]; i++ {
		if _, err := groth16.Prove(ccs, pk, w); err != nil {
			return fmt.Errorf("warm up: %w", err)
		}
	}
	timings := make([]time.Duration, numbers[1])
	proofs := make([]groth16.Proof, len(timings))
	for i := range timings {
		start := time.Now()
		proof, err := groth16.Prove(ccs, pk, w)
		timings[i] = time.Since(start)
		if err != nil {
			return fmt.Errorf("prove: %w", err)
		}
		proofs[i] = proof
	}
	for i, proof := range proofs {
		if err := groth16.Verify(proof, vk, public); err != nil {
			return fmt.Errorf("verify proof %d: %w", i+1, err)
		}
	}
	if err := groth16.Verify(proofs[0], vk, invalid); err == nil {
		return fmt.Errorf("Gnark accepted the changed statement")
	}

	fmt.Printf("verified constraints=%d wires=%d threads=%d\n",
		ccs.GetNbConstraints(), ccs.GetNbPublicVariables()+ccs.GetNbSecretVariables(), numbers[0])
	fmt.Println("changed statement rejected by Gnark")
	for _, elapsed := range timings {
		fmt.Printf("gnark_prove_ns=%d\n", elapsed.Nanoseconds())
	}
	return nil
}

func readStatement(path string) (*big.Int, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var public map[string]string
	if err := json.Unmarshal(bytes, &public); err != nil {
		return nil, err
	}
	value, ok := new(big.Int).SetString(public["public_hash"], 10)
	if len(public) != 1 || !ok || value.Sign() < 0 || value.Cmp(ecc.BN254.ScalarField()) >= 0 {
		return nil, fmt.Errorf("%s: expected one canonical public_hash", path)
	}
	return value, nil
}

// readR1CS reads an iden3 `.r1cs` file (the format circom writes and snarkjs
// reads: https://github.com/iden3/r1csfile/blob/master/doc/r1cs_bin_format.md)
// into a gnark R1CS. Wire 0 is the constant one in both; the public wires
// follow it and every other wire is a secret input.
func readR1CS(path string) (constraint.ConstraintSystem, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := &reader{r: bufio.NewReaderSize(f, 1<<20)}
	if string(r.bytes(4)) != "r1cs" || r.u32() != 1 {
		return nil, fmt.Errorf("%s: not an iden3 r1cs (version 1) file", path)
	}
	sections := r.u32()
	var ccs *cs_bn254.R1CS
	var gate constraint.BlueprintID
	var fieldSize int
	var wires, rows uint32
	for s := uint32(0); s < sections && r.err == nil; s++ {
		kind, size := r.u32(), r.u64()
		start := r.n
		switch {
		case kind == 1:
			if ccs != nil {
				return nil, fmt.Errorf("%s: two headers", path)
			}
			fieldSize = int(r.u32())
			if err := checkPrime(r.bytes(fieldSize)); err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			var pubOut, pubIn uint32
			wires, pubOut, pubIn = r.u32(), r.u32(), r.u32()
			r.u32() // private inputs: every non-public wire is a secret input here
			r.u64() // labels
			rows = r.u32()
			if r.err != nil {
				break
			}
			if uint64(pubOut)+uint64(pubIn)+1 > uint64(wires) {
				return nil, fmt.Errorf("%s: %d public wires of %d", path, uint64(pubOut)+uint64(pubIn), wires)
			}
			// Room for the rows ahead of reading them, up to a bound: the count
			// is the file's word.
			ccs = cs_bn254.NewR1CS(int(min(rows, 1<<20)))
			ccs.AddPublicVariable("1")
			public := int(pubOut + pubIn)
			for i := 1; i <= public; i++ {
				ccs.AddPublicVariable("public_" + strconv.Itoa(i))
			}
			for i := public + 1; i < int(wires); i++ {
				ccs.AddSecretVariable("w_" + strconv.Itoa(i))
			}
			gate = ccs.AddBlueprint(&constraint.BlueprintGenericR1C{})
		case kind == 2:
			if ccs == nil {
				return nil, fmt.Errorf("%s: the constraints come before the header", path)
			}
			for i := uint32(0); i < rows && r.err == nil; i++ {
				var row constraint.R1C
				row.L = r.lc(ccs, fieldSize, wires)
				row.R = r.lc(ccs, fieldSize, wires)
				row.O = r.lc(ccs, fieldSize, wires)
				if r.err == nil {
					ccs.AddR1C(row, gate)
				}
			}
		default:
			r.skip(size)
		}
		r.ends(kind, start, size)
	}
	if r.err != nil {
		return nil, fmt.Errorf("%s: %w", path, r.err)
	}
	if ccs == nil || ccs.GetNbConstraints() != int(rows) {
		return nil, fmt.Errorf("%s: missing the header or the constraints", path)
	}
	return ccs, nil
}

// readWitness reads an iden3 `.wtns` file (snarkjs' witness format): the value
// of every wire, in wire order, the constant one first.
func readWitness(path string, public, secret int) (witness.Witness, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := &reader{r: bufio.NewReaderSize(f, 1<<20)}
	if string(r.bytes(4)) != "wtns" || r.u32() != 2 {
		return nil, fmt.Errorf("%s: not an iden3 wtns (version 2) file", path)
	}
	sections := r.u32()
	var values []fr.Element
	var fieldSize int
	var n uint32
	for s := uint32(0); s < sections && r.err == nil; s++ {
		kind, size := r.u32(), r.u64()
		start := r.n
		switch kind {
		case 1:
			fieldSize = int(r.u32())
			if err := checkPrime(r.bytes(fieldSize)); err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			n = r.u32()
		case 2:
			// The count is the header's, and a header can say anything: the
			// circuit's own wire count bounds what is allocated for it.
			if int64(n) != int64(1+public+secret) {
				return nil, fmt.Errorf("%s: %d values for a circuit of %d wires (was the key made for another build of the circuit?)", path, n, 1+public+secret)
			}
			values = make([]fr.Element, n)
			for i := range values {
				values[i] = r.element(fieldSize)
			}
		default:
			r.skip(size)
		}
		r.ends(kind, start, size)
	}
	if r.err != nil {
		return nil, fmt.Errorf("%s: %w", path, r.err)
	}
	if len(values) != 1+public+secret {
		return nil, fmt.Errorf("%s: no values for the circuit's %d wires", path, 1+public+secret)
	}
	var one fr.Element
	one.SetOne()
	if !values[0].Equal(&one) {
		return nil, fmt.Errorf("%s: witness wire 0 must be one", path)
	}
	w, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	ch := make(chan any, 1024)
	go func() {
		for i := 1; i < len(values); i++ {
			ch <- &values[i]
		}
		close(ch)
	}()
	if err := w.Fill(public, secret, ch); err != nil {
		return nil, err
	}
	return w, nil
}

func checkPrime(le []byte) error {
	if new(big.Int).SetBytes(reversed(le)).Cmp(fr.Modulus()) != 0 {
		return fmt.Errorf("not over the BN254 scalar field")
	}
	return nil
}

func reversed(b []byte) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[len(b)-1-i] = v
	}
	return out
}

// reader reads the little-endian iden3 containers, keeping the first error.
type reader struct {
	r   *bufio.Reader
	n   uint64 // bytes read so far
	err error
	buf [64]byte
}

// ends checks that the section begun at byte `start` took the `size` bytes its
// header gave it: a file whose sections disagree with their sizes is not read
// as if it were sound.
func (r *reader) ends(kind uint32, start, size uint64) {
	if r.err == nil && r.n-start != size {
		r.err = fmt.Errorf("section %d is %d bytes and says %d", kind, r.n-start, size)
	}
}

func (r *reader) bytes(n int) []byte {
	if n > len(r.buf) {
		r.err = fmt.Errorf("field elements of %d bytes", n)
	}
	if r.err != nil {
		return r.buf[:0]
	}
	_, r.err = io.ReadFull(r.r, r.buf[:n])
	r.n += uint64(n)
	return r.buf[:n]
}

func (r *reader) u32() uint32 {
	b := r.bytes(4)
	if r.err != nil {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}

func (r *reader) u64() uint64 {
	b := r.bytes(8)
	if r.err != nil {
		return 0
	}
	return binary.LittleEndian.Uint64(b)
}

func (r *reader) skip(n uint64) {
	if r.err == nil {
		_, r.err = io.CopyN(io.Discard, r.r, int64(n))
		r.n += n
	}
}

func (r *reader) element(size int) (e fr.Element) {
	b := r.bytes(size)
	if r.err == nil {
		e.SetBytes(reversed(b))
	}
	return e
}

func (r *reader) lc(ccs *cs_bn254.R1CS, fieldSize int, wires uint32) constraint.LinearExpression {
	n := r.u32()
	if r.err != nil {
		return nil
	}
	// No more terms than wires are allocated ahead of reading them: the count
	// is the file's word.
	lc := make(constraint.LinearExpression, 0, min(n, wires))
	for i := uint32(0); i < n && r.err == nil; i++ {
		wire := r.u32()
		e := r.element(fieldSize)
		if r.err == nil && wire >= wires {
			r.err = fmt.Errorf("a term on wire %d of %d", wire, wires)
			return nil
		}
		var c constraint.U64
		copy(c[:], e[:])
		lc = append(lc, ccs.MakeTerm(c, int(wire)))
	}
	return lc
}
