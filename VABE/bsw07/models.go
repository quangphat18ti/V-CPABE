package bsw07

import (
	. "cpabe-prototype/VABE/access-policy"
	"github.com/cloudflare/bn256"
	"math/big"
)

type Secrete big.Int
type Message bn256.GT

// PublicKey represents the public parameters
type PublicKey struct {
	G1       *bn256.G1
	G2       *bn256.G2
	H        *bn256.G2
	F        *bn256.G2
	EggAlpha *bn256.GT
}

// MasterSecretKey represents the master secret key
type MasterSecretKey struct {
	Beta    *big.Int
	G1Alpha *bn256.G1
}

// SecretKey represents a user's secret key
type SecretKey struct {
	AttrList []string
	K0       *bn256.G1 // K0 = g1^(α+r)/B
	K        map[string]*AttributeKey
}

type SecretKeyProof struct {
	V *bn256.GT // e(g1, g2)^r
}

// AttributeKey represents keys for each attribute
type AttributeKey struct {
	K1 *bn256.G1 // CommitShareSecretG2 = (g1^rand) * hash[attr]^rand
	K2 *bn256.G2 //  HashPowShareSecretG1 = g2^rand
}

// Ciphertext represents encrypted data
type Ciphertext struct {
	Policy AccessPolicy
	C0     *bn256.G2 // C0 = h^s
	CM     *bn256.GT // C_m = e(g1^α, g2)^s * M
	C      []*AttributeCiphertext
}

// AttributeCiphertext represents ciphertext components for each attribute
type AttributeCiphertext struct {
	C1 *bn256.G2 // C1 = g2^share
	C2 *bn256.G1 // C2 = H[attr]^share
}

type CiphertextProof struct {
	CommitRootSecretG1            *bn256.G1     // Commitment to the secret
	CommitShareSecretInnerNodesG2 []*bn256.G2   // Commitments to the share secrets of inner nodes
	CommitAllPolynomialG2         [][]*bn256.G2 // Commitments to all polynomial coefficients of all inner nodes
}

// PolicyNode represents a node in the access policy tree
type Node struct {
	Type      NodeType
	Attribute string
	Index     int // Index of the attribute in the universe, if applicable
	Secrete   Secrete

	Children    []*Node
	Polynomial  []big.Int // Coefficients of the polynomial for this node
	Threshold   int
	InnerCipher *InnerNodeCiphertext

	isLeaf     bool
	LeafCipher *LeafNodeCiphertext // Only for leaf nodes
}

type InnerNodeCiphertext struct {
	CommitShareSecretG2     *bn256.G2   // C[attr] = g2^share
	CommitPolynomialCoeffG2 []*bn256.G2 // e_i = g2^poly[i] for each coefficient in the polynomial
}

type LeafNodeCiphertext struct {
	CommitShareSecretG2  *bn256.G2 // C[attr] = g2^share
	HashPowShareSecretG1 *bn256.G1 // C'[attr] = Hash(attr)^share
}

type VerificationParams struct {
	KeyProof        *SecretKeyProof
	CiphertextProof *CiphertextProof
}
