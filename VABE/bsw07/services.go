package bsw07

import (
	"cpabe-prototype/pkg/utilities"
	"fmt"
	"github.com/cloudflare/bn256"
)

type BSW07S struct {
	Verbose bool   `json:"verbose"`
	Salt    []byte `json:"Salt"`
	// Salt for hashing to G1, can be used to ensure uniqueness
}

func NewBSW07S(verbose bool, salt []byte) *BSW07S {
	if salt == nil {
		salt = []byte("default_salt") // Default Salt if none provided
	}

	return &BSW07S{
		Verbose: verbose,
		Salt:    salt,
	}
}

func (scheme *BSW07S) hashToG1(data []byte) (*bn256.G1, error) {
	hash := bn256.HashG1(data, scheme.Salt)
	if hash == nil {
		return nil, fmt.Errorf("failed to hash data to G1")
	}
	return hash, nil
}

func SaveScheme(filename string, scheme *BSW07S) error {
	return utilities.SaveToFile(filename, scheme)
}

func LoadScheme(filename string) (*BSW07S, error) {
	var scheme BSW07S
	err := utilities.LoadFromFile(filename, &scheme)
	if err != nil {
		return nil, fmt.Errorf("failed to load scheme from file: %w", err)
	}
	return &scheme, nil
}
