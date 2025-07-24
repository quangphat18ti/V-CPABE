package waters11

import (
	. "cpabe-prototype/VABE/access-policy"
	"cpabe-prototype/VABE/waters11/models"
	"cpabe-prototype/pkg/utilities"
	"fmt"
	"github.com/cloudflare/bn256"
)

type Waters11Interface interface {
	Setup() (*models.PublicKey, *models.MasterSecretKey, error)
	KeyGen(msk models.MasterSecretKey, pk models.PublicKey, userAttributes []string) (*models.SecretKey, error)
	Encrypt(pk models.PublicKey, msg models.Message, tree AccessPolicy) (*models.Ciphertext, error)
	Decrypt(pk models.PublicKey, ciphertext models.Ciphertext, sk models.SecretKey) (*models.Message, error)
}

type Waters11 struct {
	Verbose bool   `json:"verbose"`
	Salt    []byte `json:"Salt"`
}

func NewWaters11(verbose bool, salt []byte) *Waters11 {
	if salt == nil {
		salt = []byte("default_salt") // Default Salt if none provided
	}

	return &Waters11{
		Verbose: verbose,
		Salt:    salt,
	}
}

func (w *Waters11) hashToG1(data []byte) (*bn256.G1, error) {
	// Hash data to G1 using a cryptographic hash function
	hash := bn256.HashG1(data, w.Salt)
	if hash == nil {
		return nil, fmt.Errorf("failed to hash data to G1")
	}
	return hash, nil
}

func SaveScheme(filename string, scheme *Waters11) error {
	return utilities.SaveToFile(filename, scheme)
}

func LoadScheme(filename string) (*Waters11, error) {
	var scheme Waters11
	err := utilities.LoadFromFile(filename, &scheme)
	if err != nil {
		return nil, fmt.Errorf("failed to load scheme from file: %w", err)
	}
	return &scheme, nil
}
