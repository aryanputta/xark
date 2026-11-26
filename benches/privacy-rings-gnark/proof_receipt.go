package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	bn254 "github.com/consensys/gnark/backend/groth16/bn254"
)

func g1Coordinates(p curve.G1Affine) [2]string {
	var n big.Int
	return [2]string{p.X.BigInt(&n).String(), p.Y.BigInt(&n).String()}
}

func g2Coordinates(p curve.G2Affine) [4]string {
	var n big.Int
	return [4]string{
		p.X.A0.BigInt(&n).String(), p.X.A1.BigInt(&n).String(),
		p.Y.A0.BigInt(&n).String(), p.Y.A1.BigInt(&n).String(),
	}
}

// Serialize the public verifying key and proof points for commitment-free BN254.
// The receipt never receives the proving key or any witness data.
func writeProofReceipt(path string, key groth16.VerifyingKey, proofs []groth16.Proof) error {
	vk, ok := key.(*bn254.VerifyingKey)
	if !ok || len(vk.G1.K) != 2 || len(vk.CommitmentKeys) != 0 || len(vk.PublicAndCommitmentCommitted) != 0 {
		return fmt.Errorf("expected a commitment-free BN254 key with one public input")
	}
	encodedKey := [5]any{
		g1Coordinates(vk.G1.Alpha), g2Coordinates(vk.G2.Beta),
		g2Coordinates(vk.G2.Gamma), g2Coordinates(vk.G2.Delta),
		[2][2]string{g1Coordinates(vk.G1.K[0]), g1Coordinates(vk.G1.K[1])},
	}
	encodedProofs := make([][3]any, len(proofs))
	for i, entry := range proofs {
		proof, ok := entry.(*bn254.Proof)
		if !ok || len(proof.Commitments) != 0 {
			return fmt.Errorf("proof %d is not commitment-free BN254", i+1)
		}
		encodedProofs[i] = [3]any{g1Coordinates(proof.Ar), g2Coordinates(proof.Bs), g1Coordinates(proof.Krs)}
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(file).Encode([2]any{encodedKey, encodedProofs}); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}
