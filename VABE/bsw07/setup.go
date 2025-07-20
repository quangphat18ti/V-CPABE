package bsw07

import (
	"cpabe-prototype/VABE/bsw07/models"
	"crypto/rand"
	"fmt"
	"github.com/cloudflare/bn256"
	"time"
)

// Setup generates the public key and master secret key for the BSW07 scheme.
func (scheme *BSW07S) Setup() (*models.PublicKey, *models.MasterSecretKey, error) {
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

	pk := &models.PublicKey{
		G1:       g1,
		G2:       g2,
		H:        h,
		EggAlpha: eggAlpha,
	}

	msk := &models.MasterSecretKey{
		Beta:    beta,
		G1Alpha: g1Alpha,
	}

	return pk, msk, nil
}
