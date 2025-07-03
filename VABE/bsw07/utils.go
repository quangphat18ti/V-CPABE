package bsw07

import (
	. "cpabe-prototype/VABE/access-policy"
)

func accesPolicyToAccessTree(pk PublicKey, policy *AccessPolicy, index int) *Node {
	if policy.NodeType == LeafNodeType {
		return &Node{
			Type:      LeafNodeType,
			Attribute: policy.Attribute,
			Index:     index,
			isLeaf:    true,
			Threshold: 1,
		}
	}

	children := make([]*Node, len(policy.Children))
	for i, child := range policy.Children {
		children[i] = accesPolicyToAccessTree(pk, &child, i+1)
	}

	threshold := 1
	if policy.NodeType == AndNodeType {
		threshold = len(children)
	}

	return &Node{
		Type:      policy.NodeType,
		Children:  children,
		Index:     index,
		Threshold: threshold,
	}
}
