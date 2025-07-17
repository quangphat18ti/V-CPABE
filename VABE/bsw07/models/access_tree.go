package models

import (
	. "cpabe-prototype/VABE/access-policy"
	"github.com/cloudflare/bn256"
	"math/big"
)

type AccessTree = *Node

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

	IsLeaf     bool
	LeafCipher *LeafNodeCiphertext // Only for leaf nodes
}

func (n *Node) PruneTree(mapAttr map[string]bool) ([]string, bool) {
	if n.IsLeaf {
		if mapAttr[n.Attribute] {
			return []string{n.Attribute}, true
		}
		return nil, false
	}

	if n.Type == OrNodeType {
		for _, child := range n.Children {
			attrs, ok := child.PruneTree(mapAttr)
			if ok {
				n.Children = []*Node{child}
				return attrs, true
			}
		}

		return nil, false
	}

	if n.Type == AndNodeType {
		mapAuthorizedAttrs := make(map[string]bool)

		for _, child := range n.Children {
			attrs, ok := child.PruneTree(mapAttr)
			if !ok {
				return nil, false
			}

			for _, attr := range attrs {
				mapAuthorizedAttrs[attr] = true
			}
		}

		authorizedAttrs := make([]string, 0)
		for attr := range mapAuthorizedAttrs {
			authorizedAttrs = append(authorizedAttrs, attr)
		}

		return authorizedAttrs, true
	}

	panic("Unknown node type in PruneTree")
}

type InnerNodeCiphertext struct {
	CommitShareSecretG2     *bn256.G2   // C[attr] = g2^share
	CommitPolynomialCoeffG2 []*bn256.G2 // e_i = g2^poly[i] for each coefficient in the polynomial
}

type LeafNodeCiphertext struct {
	CommitShareSecretG2  *bn256.G2 // C[attr] = g2^share
	HashPowShareSecretG1 *bn256.G1 // C'[attr] = Hash(attr)^share
}
