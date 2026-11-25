package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func knownBundle() []byte {
	const count = 3
	_, _, b1, b2 := bn254.Generators()
	g1, g2 := b1.RawBytes(), b2.RawBytes()
	data := make([]byte, headerSize+count*recordSize+resultSize)
	copy(data, magic)
	binary.LittleEndian.PutUint32(data[len(magic):headerSize], count)
	for i := 0; i < 2; i++ {
		start := headerSize + i*recordSize
		copy(data[start+fr.Bytes:], g1[:])
		copy(data[start+fr.Bytes+g1Size:], g2[:])
	}
	// Generator, zero times generator, and five times infinity sum to the generator.
	data[headerSize+fr.Bytes-1] = 1
	data[headerSize+2*recordSize+fr.Bytes-1] = 5
	copy(data[headerSize+count*recordSize:], g1[:])
	copy(data[headerSize+count*recordSize+g1Size:], g2[:])
	return data
}

func TestRejectMalformedBundle(t *testing.T) {
	cases := []struct {
		name string
		edit func([]byte) []byte
	}{
		{"truncated header", func(data []byte) []byte { return data[:4] }},
		{"wrong magic", func(data []byte) []byte { data[0] = 'Y'; return data }},
		{"truncated body", func(data []byte) []byte { return data[:len(data)-1] }},
		{"trailing bytes", func(data []byte) []byte { return append(data, 0) }},
		{"wrong count", func(data []byte) []byte {
			binary.LittleEndian.PutUint32(data[len(magic):headerSize], ^uint32(0))
			return data
		}},
		{"nonconstant first scalar", func(data []byte) []byte {
			data[headerSize+fr.Bytes-1] = 2
			return data
		}},
		{"noncanonical scalar", func(data []byte) []byte {
			start := headerSize + recordSize
			fr.Modulus().FillBytes(data[start : start+fr.Bytes])
			return data
		}},
		{"off-curve G1", func(data []byte) []byte {
			data[headerSize+fr.Bytes+g1Size-1] ^= 1
			return data
		}},
		{"compressed G2", func(data []byte) []byte {
			data[headerSize+fr.Bytes+g1Size] |= 0x80
			return data
		}},
		{"noncanonical reference G2", func(data []byte) []byte {
			data[len(data)-g2Size] = 0xff
			return data
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseBundle(tc.edit(knownBundle())); err == nil {
				t.Fatal("accepted malformed bundle")
			}
		})
	}
}

func runFixture(t *testing.T, data []byte) (string, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vector.bin")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err := run([]string{path, "2", "2", "2", "1"}, &output)
	return output.String(), err
}

func TestBenchmarkVerifiedOutput(t *testing.T) {
	output, err := runFixture(t, knownBundle())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
	if len(lines) != 5 || lines[0] != "query msm gnark verified: terms=3 threads=2 tasks=2 samples=2 warmups=1" {
		t.Fatalf("unexpected receipt %q", output)
	}
	for i, prefix := range []string{
		"query msm gnark: query=b1 sample=1 gnark_ns=",
		"query msm gnark: query=b1 sample=2 gnark_ns=",
		"query msm gnark: query=b2 sample=1 gnark_ns=",
		"query msm gnark: query=b2 sample=2 gnark_ns=",
	} {
		if !strings.HasPrefix(lines[i+1], prefix) {
			t.Errorf("sample %d did not match %q", i+1, prefix)
		}
	}
}

func TestBenchmarkRejectsSecondQueryBeforeReporting(t *testing.T) {
	data := knownBundle()
	clear(data[len(data)-g2Size:])
	output, err := runFixture(t, data)
	if err == nil || !strings.Contains(err.Error(), "b2 iteration 1: MSM disagrees with the reference") || output != "" {
		t.Fatalf("wanted an error and no receipts, got error %v and output %q", err, output)
	}
}
