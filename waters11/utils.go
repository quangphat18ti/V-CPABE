package waters11

import (
	"fmt"
	"regexp"
	"strings"
)

func tokenize(input string) []string {
	re := regexp.MustCompile(`\(|\)|AND|OR|[a-zA-Z0-9_]+`)
	return re.FindAllString(input, -1)
}

func prettyPrint(node *AccessPolicy) {
	var dfs func(*AccessPolicy, int)
	dfs = func(n *AccessPolicy, depth int) {
		fmt.Printf("%s- %s", strings.Repeat("  ", depth), n.NodeType)
		if n.NodeType == LeafNodeType {
			fmt.Printf(": %s", n.Attribute)
		}
		fmt.Println()
		for _, child := range n.Children {
			dfs(child, depth+1)
		}
	}
	dfs(node, 0)
}
