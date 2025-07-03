package waters11

import (
	"crypto/rand"
	"fmt"
	"github.com/cloudflare/bn256"
	"strconv"
	"time"
)

type Waters11Interface interface {
	Setup(securityParams SecurityParameter) (*PublicKey, *MasterSecretKey, error)
	KeyGen(msk MasterSecretKey, pk PublicKey, userAttributes []string) (*SecretKey, error)
	Encrypt(pk PublicKey, msg Message, tree PolicyTree) (*Ciphertext, error)
	Decrypt(pk PublicKey, ciphertext Ciphertext, sk SecretKey) (*Message, error)
}

type Waters11 struct {
	Verbose bool
	salt    []byte // salt for hashing to G1, can be used to ensure uniqueness
	UniSize int    // Universe size, number of attributes in the system
}

func NewWaters11(verbose bool, salt []byte) *Waters11 {
	if salt == nil {
		salt = []byte("default_salt") // Default salt if none provided
	}

	return &Waters11{
		Verbose: verbose,
		salt:    salt,
	}
}

func (w *Waters11) hashToG1(data []byte) (*bn256.G1, error) {
	// Hash data to G1 using a cryptographic hash function
	hash := bn256.HashG1(data, w.salt)
	if hash == nil {
		return nil, fmt.Errorf("failed to hash data to G1")
	}
	return hash, nil
}

// Setup generates the public key and master secret key for the Waters-11 scheme.
func (w *Waters11) Setup(securityParams SecurityParameter) (*PublicKey, *MasterSecretKey, error) {
	start := time.Now()
	defer func() {
		fmt.Printf("Setup time: %v\n", time.Since(start))
	}()

	if w.Verbose {
		fmt.Println("Setup algorithm:")
	}

	w.UniSize = securityParams.UniSize

	// Generate random elements
	_, g1, err := bn256.RandomG1(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random g1: %w", err)
	}

	_, g2, err := bn256.RandomG2(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random g2: %w", err)
	}

	// Generate random α
	alpha, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return nil, nil, err
	}

	// Compute g1^α
	g1Alpha := new(bn256.G1).ScalarMult(g1, alpha)

	// Compute e(g1^α, g2)
	eggAlpha := bn256.Pair(g1Alpha, g2)

	// Generate random a
	a, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random a: %w", err)
	}

	// Compute g1^a
	g1A := new(bn256.G1).ScalarMult(g1, a)

	// Generate hash functions h[1], h[2], ..., h[uni_size]
	h := make([]*bn256.G1, w.UniSize+1) // h[0] is unused, indexing starts from 1
	for i := 1; i <= w.UniSize; i++ {
		_, hi, err := bn256.RandomG1(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		h[i] = hi
	}

	pk := &PublicKey{
		G1:       g1,
		G2:       g2,
		G1A:      g1A,
		H:        h,
		EggAlpha: eggAlpha,
		UniSize:  w.UniSize,
	}

	msk := &MasterSecretKey{
		G1Alpha: g1Alpha,
	}

	return pk, msk, nil
}

func (w *Waters11) KeyGen(msk MasterSecretKey, pk PublicKey, userAttributes []string) (*SecretKey, error) {
	if w.Verbose {
		fmt.Println("Key generation algorithm:")
	}

	// Pick random t
	t, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return nil, fmt.Errorf("failed to generate t: %v", err)
	}

	// Compute k0 = g1^alpha * (g1^a)^t
	g1At := new(bn256.G1).ScalarMult(pk.G1A, t)
	k0 := new(bn256.G1).Add(msk.G1Alpha, g1At)

	// Compute L = g2^t
	L := new(bn256.G2).ScalarMult(pk.G2, t)

	// Compute K[attr] = h[attr]^t for each attribute
	K := make(map[string]*bn256.G1)
	for _, attr := range userAttributes {
		attrInt, err := strconv.Atoi(attr)
		if err != nil {
			return nil, fmt.Errorf("attribute must be integer: %v", err)
		}
		if attrInt < 1 || attrInt > w.UniSize {
			return nil, fmt.Errorf("attribute %d out of range [1, %d]", attrInt, w.UniSize)
		}

		K[attr] = new(bn256.G1).ScalarMult(pk.H[attrInt], t)
	}

	return &SecretKey{
		AttrList: userAttributes,
		K0:       k0,
		L:        L,
		K:        K,
	}, nil
}

func (w *Waters11) Encrypt(pk PublicKey, msg Message, tree PolicyTree) (*Ciphertext, error) {
	//TODO implement me
	panic("implement me")
}

func (w *Waters11) Decrypt(pk PublicKey, ciphertext Ciphertext, sk SecretKey) (*Message, error) {
	//TODO implement me
	panic("implement me")
}
