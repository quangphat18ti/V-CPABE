package waters11

import (
	"cpabe-prototype/VABE/access-policy"
	"github.com/cloudflare/bn256"
	"math/big"
)

type SecurityParameter struct {
	UniSize int
}

type Message bn256.GT

type PublicKey struct {
	G1       *bn256.G1   // Generator of G1
	G2       *bn256.G2   // Generator of G2
	G1A      *bn256.G1   // g1^a
	H        []*bn256.G1 // Hash functions h_i for i in [1, uni_size]
	EggAlpha *bn256.GT   // e(g1^α, g2)
	UniSize  int         // Universe size
}

type MasterSecretKey struct {
	G1Alpha *bn256.G1 // g1^α
}

// SecretKey represents a user's secret key
type SecretKey struct {
	AttrList []string             // List of attributes
	K0       *bn256.G1            // k0 = g1^α * (g1^a)^t
	L        *bn256.G2            // L = g2^t
	K        map[string]*bn256.G1 // K[attr] = h[attr]^t
}

type AttributeKey struct {
	Attribute string
	Index     int       // Index of the attribute in the universe
	Key       *bn256.G1 // Key for the attribute, K[attr] = h[Index]^t
}

type Ciphertext struct {
	Policy *access_policy.AccessPolicy // Access policy
	C0     *bn256.G2                   // c0 = g2^s
	C      map[string]*bn256.G1        // C[attr] = (g1^a)^λ_attr / h[attr]^r_attr
	D      map[string]*bn256.G2        // D[attr] = g2^r_attr
	Cm     *bn256.GT                   // c_m = e(g1^α, g2)^s * M
}

type PolicyTree struct {
	Root    *Node // Root node of the access policy tree
	Secrete int
}

type Node struct {
	Type      access_policy.NodeType
	Attribute string
	Index     int

	Children    []*Node
	Polynomial  []*big.Int
	InnerCipher *InnerNodeCiphertext

	LeafCipher *LeafNodeCiphertext
}

type InnerNodeCiphertext struct {
	E []*bn256.GT // e = e(g1, g2)^(a*poly_child)
}

type LeafNodeCiphertext struct {
	C *bn256.G1 // C[attr] = (g1^a)^λ_attr / h[attr]^r_attr
	D *bn256.G2 // D[attr] = g2^r_attr
}
