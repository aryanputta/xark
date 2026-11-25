// query-msm times same-vector B1 and B2 MSMs against an Arkworks reference.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const (
	magic      = "XKQMSM01"
	headerSize = len(magic) + 4
	g1Size     = bn254.SizeOfG1AffineUncompressed
	g2Size     = bn254.SizeOfG2AffineUncompressed
	recordSize = fr.Bytes + g1Size + g2Size
	resultSize = g1Size + g2Size
)

type bundle struct {
	scalars []fr.Element
	b1      []bn254.G1Affine
	b2      []bn254.G2Affine
	wantB1  [g1Size]byte
	wantB2  [g2Size]byte
}

func canonicalG1(encoded []byte, point *bn254.G1Affine) bool {
	size, err := point.SetBytes(encoded)
	// SetBytes checks the curve and subgroup. The consumed size and
	// round trip also enforce the uncompressed representation.
	if err != nil || size != g1Size || !point.IsOnCurve() {
		return false
	}
	raw := point.RawBytes()
	return bytes.Equal(raw[:], encoded)
}

func canonicalG2(encoded []byte, point *bn254.G2Affine) bool {
	size, err := point.SetBytes(encoded)
	if err != nil || size != g2Size || !point.IsOnCurve() {
		return false
	}
	raw := point.RawBytes()
	return bytes.Equal(raw[:], encoded)
}

func parseBundle(data []byte) (bundle, error) {
	if len(data) < headerSize+resultSize || string(data[:len(magic)]) != magic {
		return bundle{}, fmt.Errorf("invalid bundle header")
	}
	count := uint64(binary.LittleEndian.Uint32(data[len(magic):headerSize]))
	if count == 0 || uint64(len(data)) != uint64(headerSize+resultSize)+count*uint64(recordSize) {
		return bundle{}, fmt.Errorf("record count does not match bundle length")
	}
	result := bundle{
		scalars: make([]fr.Element, int(count)),
		b1:      make([]bn254.G1Affine, int(count)),
		b2:      make([]bn254.G2Affine, int(count)),
	}
	rest := data[headerSize:]
	for i := range result.scalars {
		if err := result.scalars[i].SetBytesCanonical(rest[:fr.Bytes]); err != nil {
			return bundle{}, fmt.Errorf("noncanonical scalar at record %d", i)
		}
		if !canonicalG1(rest[fr.Bytes:fr.Bytes+g1Size], &result.b1[i]) {
			return bundle{}, fmt.Errorf("invalid B1 point at record %d", i)
		}
		if !canonicalG2(rest[fr.Bytes+g1Size:recordSize], &result.b2[i]) {
			return bundle{}, fmt.Errorf("invalid B2 point at record %d", i)
		}
		rest = rest[recordSize:]
	}
	if !result.scalars[0].IsOne() {
		return bundle{}, fmt.Errorf("record zero must carry the constant-one witness")
	}
	var expectedB1 bn254.G1Affine
	if !canonicalG1(rest[:g1Size], &expectedB1) {
		return bundle{}, fmt.Errorf("invalid expected B1 point")
	}
	var expectedB2 bn254.G2Affine
	if !canonicalG2(rest[g1Size:], &expectedB2) {
		return bundle{}, fmt.Errorf("invalid expected B2 point")
	}
	copy(result.wantB1[:], rest[:g1Size])
	copy(result.wantB2[:], rest[g1Size:])
	return result, nil
}

func measureQuery(query string, samples, warmups int, measure func() (time.Duration, error)) ([]time.Duration, error) {
	times := make([]time.Duration, 0, samples)
	for i := 0; i < samples+warmups; i++ {
		elapsed, err := measure()
		if err != nil {
			return nil, fmt.Errorf("%s iteration %d: %w", query, i+1, err)
		}
		if i >= warmups {
			times = append(times, elapsed)
		}
	}
	return times, nil
}

func benchmark(input bundle, tasks, samples, warmups int) ([]time.Duration, []time.Duration, error) {
	config := ecc.MultiExpConfig{NbTasks: tasks}
	b1, err := measureQuery("b1", samples, warmups, func() (time.Duration, error) {
		var sum bn254.G1Jac
		start := time.Now()
		_, err := sum.MultiExp(input.b1, input.scalars, config)
		elapsed := time.Since(start)
		if err != nil {
			return 0, err
		}
		var affine bn254.G1Affine
		affine.FromJacobian(&sum)
		if affine.RawBytes() != input.wantB1 {
			return 0, fmt.Errorf("MSM disagrees with the reference")
		}
		return elapsed, nil
	})
	if err != nil {
		return nil, nil, err
	}
	b2, err := measureQuery("b2", samples, warmups, func() (time.Duration, error) {
		var sum bn254.G2Jac
		start := time.Now()
		_, err := sum.MultiExp(input.b2, input.scalars, config)
		elapsed := time.Since(start)
		if err != nil {
			return 0, err
		}
		var affine bn254.G2Affine
		affine.FromJacobian(&sum)
		if affine.RawBytes() != input.wantB2 {
			return 0, fmt.Errorf("MSM disagrees with the reference")
		}
		return elapsed, nil
	})
	if err != nil {
		return nil, nil, err
	}
	return b1, b2, nil
}

func run(args []string, output io.Writer) error {
	if len(args) < 3 || len(args) > 5 {
		return fmt.Errorf("usage: query-msm <bundle> <threads> <tasks> [samples] [warmups]")
	}
	settings := [...]int{0, 0, 30, 3}
	for i, arg := range args[1:] {
		number, err := strconv.Atoi(arg)
		if err != nil || number < 0 || (i < 3 && number == 0) {
			return fmt.Errorf("threads, tasks and samples must be positive integers and warmups nonnegative")
		}
		settings[i] = number
	}
	threads, tasks, samples, warmups := settings[0], settings[1], settings[2], settings[3]
	if samples > math.MaxInt-warmups {
		return fmt.Errorf("total iterations must fit in int")
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}
	input, err := parseBundle(data)
	if err != nil {
		return err
	}
	previousThreads := runtime.GOMAXPROCS(threads)
	defer runtime.GOMAXPROCS(previousThreads)
	b1, b2, err := benchmark(input, tasks, samples, warmups)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(output, "query msm gnark verified: terms=%d threads=%d tasks=%d samples=%d warmups=%d\n", len(input.scalars), runtime.GOMAXPROCS(0), tasks, samples, warmups); err != nil {
		return err
	}
	for i, times := range [][]time.Duration{b1, b2} {
		for sample, elapsed := range times {
			if _, err := fmt.Fprintf(output, "query msm gnark: query=b%d sample=%d gnark_ns=%d\n", i+1, sample+1, elapsed.Nanoseconds()); err != nil {
				return err
			}
		}
	}
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "query-msm:", err)
		os.Exit(1)
	}
}
