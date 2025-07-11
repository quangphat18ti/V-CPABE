package access_policy

import (
	"fmt"
	"strings"
)

type NodeType string

const (
	AndNodeType  NodeType = "AndNode"
	OrNodeType   NodeType = "OrNode"
	LeafNodeType NodeType = "LeafNode"
)

type AccessPolicy struct {
	NodeType  NodeType
	Attribute string
	Children  []*AccessPolicy
}

func (a *AccessPolicy) FromString(policyStr string) (*AccessPolicy, error) {
	// Simplified policy parser - supports basic AND/OR operations and ()
	// In a full implementation, you'd need a proper parser

	policyStr = strings.TrimSpace(policyStr)

	tokens := tokenize(policyStr)

	output := []*AccessPolicy{}
	opStack := []string{}

	precedence := map[string]int{"OR": 1, "AND": 2}

	applyOperator := func(op string, right, left *AccessPolicy) *AccessPolicy {
		var nodeType NodeType
		if op == "AND" {
			nodeType = AndNodeType
		} else {
			nodeType = OrNodeType
		}
		return &AccessPolicy{
			NodeType: nodeType,
			Children: []*AccessPolicy{left, right},
		}
	}

	for _, token := range tokens {
		switch token {
		case "(":
			opStack = append(opStack, token)

		case ")":
			for len(opStack) > 0 && opStack[len(opStack)-1] != "(" {
				op := opStack[len(opStack)-1]
				opStack = opStack[:len(opStack)-1]

				if len(output) < 2 {
					return nil, fmt.Errorf("invalid expression")
				}
				right := output[len(output)-1]
				left := output[len(output)-2]
				output = output[:len(output)-2]

				output = append(output, applyOperator(op, right, left))
			}
			opStack = opStack[:len(opStack)-1] // pop "("

		case "AND", "OR":
			for len(opStack) > 0 && precedence[opStack[len(opStack)-1]] >= precedence[token] {
				op := opStack[len(opStack)-1]
				opStack = opStack[:len(opStack)-1]

				if len(output) < 2 {
					return nil, fmt.Errorf("invalid expression")
				}
				right := output[len(output)-1]
				left := output[len(output)-2]
				output = output[:len(output)-2]

				output = append(output, applyOperator(op, right, left))
			}
			opStack = append(opStack, token)

		default: // attribute
			output = append(output, &AccessPolicy{
				NodeType:  LeafNodeType,
				Attribute: token,
			})
		}
	}

	for len(opStack) > 0 {
		op := opStack[len(opStack)-1]
		opStack = opStack[:len(opStack)-1]

		if len(output) < 2 {
			return nil, fmt.Errorf("invalid expression")
		}
		right := output[len(output)-1]
		left := output[len(output)-2]
		output = output[:len(output)-2]

		output = append(output, applyOperator(op, right, left))
	}

	if len(output) != 1 {
		return nil, fmt.Errorf("invalid policy structure")
	}
	return output[0], nil
}
