package bsw07

import (
	"fmt"
	"github.com/cloudflare/bn256"
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
