package waters11

import (
	. "cpabe-prototype/VABE/access-policy"
	"cpabe-prototype/VABE/waters11/models"
	"cpabe-prototype/pkg/utilities"
	"fmt"
	"github.com/cloudflare/bn256"
	"math/big"
)

type VerifyCiphertextParams struct {
	PublicKey    models.PublicKey
	Ciphertext   models.Ciphertext
	Proof        models.CiphertextProof
	AccessPolicy AccessPolicy
}

func (scheme *Waters11) VerifyCiphertext(params VerifyCiphertextParams) (bool, error) {
	if scheme.Verbose {
		println("Verifying Ciphertext...")
	}

	if !Equal(&params.AccessPolicy, &params.Ciphertext.Policy) {
		return false, fmt.Errorf("wrong policy")
	}

	err := scheme.verifyCTNumComponents(params.Ciphertext, params.Proof, params.AccessPolicy)
	if err != nil {
		return false, err
	}

	err = scheme.verifyCTUsingSameS(params.Ciphertext, params.PublicKey, params.Proof)
	if err != nil {
		return false, fmt.Errorf("failed to verify Ciphertext using same secret: %w", err)
	}

	rootNode, err := scheme.recoverAccessTreeFromCiphertext(params.Ciphertext)
	if err != nil {
		return false, fmt.Errorf("failed to recover access tree from Ciphertext: %w", err)
	}

	index := 0
	err = scheme.verifyLeafNodes(&params.Ciphertext, &params.PublicKey, rootNode, &index)
	if err != nil {
		return false, fmt.Errorf("failed to verify leaf nodes: %w", err)
	}

	inner_count := 0
	_, err = scheme.verifyInnerNodes(&params.Ciphertext, &params.PublicKey, &params.Proof, rootNode, &inner_count)
	if err != nil {
		return false, fmt.Errorf("failed to verify inner nodes: %w", err)
	}
	return true, nil
}

func (scheme *Waters11) recoverAccessTreeFromCiphertext(ciphertext models.Ciphertext) (*models.Node, error) {
	index := 0
	rootNode := accesPolicyToAccessTree(&ciphertext.Policy, &index)
	if rootNode == nil {
		return nil, fmt.Errorf("failed to convert access policy to tree")
	}

	var indexInList int = 0
	err := scheme.distributeCiphertextToNodes(ciphertext, rootNode, &indexInList)
	if err != nil {
		return nil, err
	}

	if indexInList != len(ciphertext.C) {
		return nil, fmt.Errorf("number of leaf nodes in Ciphertext and access tree do not match")
	}

	return rootNode, nil
}

func (scheme *Waters11) distributeCiphertextToNodes(ciphertext models.Ciphertext, node *models.Node, idInList *int) error {
	if *idInList > len(ciphertext.C) {
		return fmt.Errorf("number of leaf nodes in Ciphertext and access tree do not match")
	}

	if node.IsLeaf {
		node.LeafCipher = &models.LeafNodeCiphertext{
			HashPowRandMulSecretG1: ciphertext.C[*idInList].C1,
			CommitRandomSecretG2:   ciphertext.C[*idInList].C2,
		}
		*idInList++
		return nil
	}

	for _, child := range node.Children {
		err := scheme.distributeCiphertextToNodes(ciphertext, child, idInList)
		if err != nil {
			return err
		}
	}

	return nil
}

func (scheme *Waters11) verifyCTNumComponents(ciphertext models.Ciphertext, proof models.CiphertextProof, accessPolicy AccessPolicy) error {
	// check access_policy with Ciphertext.accees_policy
	numLeaves := CountLeafNodes(&accessPolicy)
	totalNodes := CountTotalNodes(&accessPolicy)
	numInnerNodes := totalNodes - numLeaves

	if len(ciphertext.C) != numLeaves {
		return fmt.Errorf("wrong number of leaves in Ciphertext")
	}

	if len(proof.InnerNodeCiphertexts) != numInnerNodes {
		return fmt.Errorf("wrong number of inner nodes in Ciphertext Proof")
	}

	if len(proof.EggCommitAllPolynomial) != numInnerNodes {
		return fmt.Errorf("wrong number of inner nodes in Ciphertext Proof")
	}

	return nil
}

func (scheme *Waters11) verifyCTUsingSameS(ciphertext models.Ciphertext, pk models.PublicKey, proof models.CiphertextProof) error {
	// e(ciphertext.C0, g2) = e(g1, proof.CommitRootSecretG2)
	left := bn256.Pair(ciphertext.C0, pk.G2)
	right := bn256.Pair(pk.G1, proof.CommitRootSecretG2)
	if !utilities.CompareGTByString(left, right) {
		if scheme.Verbose {
			fmt.Println("Verification failed: e(CommitRootSecretG2, g2) does not equal e(g1, Ciphertext.InnerNodeCiphertexts[0])")
		}
		return fmt.Errorf("e(CommitRootSecretG2, g2) does not equal e(g1, Ciphertext.InnerNodeCiphertexts[0])")
	}

	// eggASecrete = e(g1, Ciphertext.C0)
	left = proof.EggASecret
	right = bn256.Pair(pk.G1A, proof.CommitRootSecretG2)
	if !utilities.CompareGTByString(left, right) {
		if scheme.Verbose {
			fmt.Println("Verification failed: e(CommitRootSecretG2, h) does not equal e(g1, Ciphertext.C0)")
		}
		return fmt.Errorf("e(CommitRootSecretG2, h) does not equal e(g1, Ciphertext.C0)")
	}

	return nil
}

func (scheme *Waters11) verifyLeafNodes(ciphertext *models.Ciphertext, pk *models.PublicKey, root *models.Node, i *int) error {
	if root == nil {
		return nil
	}

	if root.Type == LeafNodeType {
		// e(Hash(attri), C[i]) = e(C', g2)
		//hashG1, err := scheme.hashToG1([]byte(root.Attribute))
		//if err != nil {
		//	return fmt.Errorf("failed to hash attribute %s: %w", root.Attribute, err)
		//}
		//
		//left := bn256.Pair(hashG1, ciphertext.C[*i].C1)
		//right := bn256.Pair(ciphertext.C[*i].C2, pk.G2)
		//if !utilities.CompareGTByString(left, right) {
		//	return fmt.Errorf("e(Hash(%s), C[%d]) does not equal e(C', g2)", root.Attribute, *i)
		//}
		*i++
		return nil
	}

	for _, child := range root.Children {
		err := scheme.verifyLeafNodes(ciphertext, pk, child, i)
		if err != nil {
			return fmt.Errorf("failed to verify leaf node: %w", err)
		}
	}

	return nil
}

func (scheme *Waters11) verifyInnerNodes(ciphertext *models.Ciphertext, pk *models.PublicKey, proof *models.CiphertextProof, root *models.Node, innerCount *int) (*bn256.GT, error) {
	if root == nil {
		return nil, nil
	}

	if root.Type == LeafNodeType {
		//return root.LeafCipher.CommitShareSecretG2, nil
		c := root.LeafCipher
		hashToG1, err := scheme.hashToG1([]byte(root.Attribute))
		if err != nil {
			return nil, fmt.Errorf("failed to hash attribute %s to G1: %w", root.Attribute, err)
		}
		eCG2 := bn256.Pair(c.HashPowRandMulSecretG1, pk.G2)
		eHashC2 := bn256.Pair(hashToG1, c.CommitRandomSecretG2)
		h := new(bn256.GT).Add(eCG2, eHashC2)
		return h, nil
	}

	// h(child_u) = h(u) x (EggCommitAllPolynomial[i]^[index(u)^i]
	E := proof.EggCommitAllPolynomial[*innerCount]

	c := proof.InnerNodeCiphertexts[*innerCount]
	hashToG1, err := scheme.hashToG1([]byte(root.Attribute))
	if err != nil {
		return nil, fmt.Errorf("failed to hash attribute %s to G1: %w", root.Attribute, err)
	}
	eCG2 := bn256.Pair(c.C1, pk.G2)
	eHashC2 := bn256.Pair(hashToG1, c.C2)
	h := new(bn256.GT).Add(eCG2, eHashC2)
	E[0] = h

	*innerCount++

	for _, child := range root.Children {
		h_child, err := scheme.verifyInnerNodes(ciphertext, pk, proof, child, innerCount)
		if err != nil {
			return nil, err
		}

		right := calcPolynomialCommitment(E, child.Index)
		if !utilities.CompareGTByString(h_child, right) {
			return nil, fmt.Errorf("secret commitment wrong for child node with index %d", child.Index)
		}
	}

	return h, nil
}

func calcPolynomialCommitment(E []*bn256.GT, idx int) *bn256.GT {
	deg := len(E) - 1

	var result *bn256.GT = nil

	idxPower := big.NewInt(1)
	idxBig := big.NewInt(int64(idx))

	for i := 0; i <= deg; i++ {
		temp := new(bn256.GT).ScalarMult(E[i], idxPower)

		// result = result + E[i] * idx^i
		if result == nil {
			result = temp
		} else {
			result.Add(result, temp)
		}

		if i < deg {
			idxPower.Mul(idxPower, idxBig)
		}
	}

	return result
}
