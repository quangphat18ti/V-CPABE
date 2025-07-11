package bsw07

import (
	"crypto/rand"
	"fmt"
	"github.com/cloudflare/bn256"
	"time"
)

type BSW07S struct {
	Verbose bool
	salt    []byte // salt for hashing to G1, can be used to ensure uniqueness
}

func NewBSW07S(verbose bool, salt []byte) *BSW07S {
	if salt == nil {
		salt = []byte("default_salt") // Default salt if none provided
	}

	return &BSW07S{
		Verbose: verbose,
		salt:    salt,
	}
}

func (scheme *BSW07S) hashToG1(data []byte) (*bn256.G1, error) {
	hash := bn256.HashG1(data, scheme.salt)
	if hash == nil {
		return nil, fmt.Errorf("failed to hash data to G1")
	}
	return hash, nil
}

// Setup generates the public key and master secret key for the BSW07 scheme.
func (scheme *BSW07S) Setup() (*PublicKey, *MasterSecretKey, error) {
	start := time.Now()
	defer func() {
		fmt.Printf("Setup time: %v\n", time.Since(start))
	}()

	if scheme.Verbose {
		fmt.Println("Setup algorithm:")
	}

	// Generate random elements
	_, g1, err := bn256.RandomG1(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random g1: %w", err)
	}

	_, g2, err := bn256.RandomG2(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random g2: %w", err)
	}

	// Generate random αlpha
	alpha, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random alpha: %w", err)
	}

	// Generate random beta
	beta, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random beta: %w", err)
	}

	// Compute public key components
	h := new(bn256.G2).ScalarMult(g2, beta)

	//betaInv := new(big.Int).ModInverse(beta, bn256.Order)
	//f := new(bn256.G2).ScalarMult(g2, betaInv)

	// Compute e(g,g)^α
	g1Alpha := new(bn256.G1).ScalarMult(g1, alpha)
	eggAlpha := bn256.Pair(g1Alpha, g2)

	pk := &PublicKey{
		G1:       g1,
		G2:       g2,
		H:        h,
		EggAlpha: eggAlpha,
	}

	msk := &MasterSecretKey{
		Beta:    beta,
		G1Alpha: g1Alpha,
	}

	return pk, msk, nil
}
