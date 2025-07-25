package bsw07

import (
	. "cpabe-prototype/VABE/access-policy"
	"cpabe-prototype/VABE/bsw07/models"
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

func (scheme *BSW07S) VerifyCiphertext(params VerifyCiphertextParams) (bool, error) {
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

	index = 0
	_, err = scheme.verifyInnerNodes(&params.Ciphertext, &params.PublicKey, &params.Proof, rootNode, &index)
	if err != nil {
		return false, fmt.Errorf("failed to verify inner nodes: %w", err)
	}
	return true, nil
}

func (scheme *BSW07S) verifyCTNumComponents(ciphertext models.Ciphertext, proof models.CiphertextProof, accessPolicy AccessPolicy) error {
	// check access_policy with Ciphertext.accees_policy
	numLeaves := CountLeafNodes(&accessPolicy)
	totalNodes := CountTotalNodes(&accessPolicy)
	numInnerNodes := totalNodes - numLeaves

	if len(ciphertext.C) != numLeaves {
		return fmt.Errorf("wrong number of leaves in Ciphertext")
	}

	if len(proof.CommitShareSecretInnerNodesG2) != numInnerNodes {
		return fmt.Errorf("wrong number of inner nodes in Ciphertext Proof")
	}

	if len(proof.CommitAllPolynomialG2) != numInnerNodes {
		return fmt.Errorf("wrong number of inner nodes in Ciphertext Proof")
	}

	return nil
}

func (scheme *BSW07S) verifyCTUsingSameS(ciphertext models.Ciphertext, pk models.PublicKey, proof models.CiphertextProof) error {
	// e(CommitRootSecretG2, g2) = e(g1, Ciphertext.InnerNodeCiphertexts[0])
	left := bn256.Pair(proof.CommitRootSecretG1, pk.G2)
	right := bn256.Pair(pk.G1, proof.CommitShareSecretInnerNodesG2[0])
	if !utilities.CompareGTByString(left, right) {
		if scheme.Verbose {
			fmt.Println("Verification failed: e(CommitRootSecretG2, g2) does not equal e(g1, Ciphertext.InnerNodeCiphertexts[0])")
		}
		return fmt.Errorf("e(CommitRootSecretG2, g2) does not equal e(g1, Ciphertext.InnerNodeCiphertexts[0])")
	}

	// e(CommitRootSecretG2, h) = e(g1, Ciphertext.C0)
	left = bn256.Pair(proof.CommitRootSecretG1, pk.H)
	right = bn256.Pair(pk.G1, ciphertext.C0)
	if !utilities.CompareGTByString(left, right) {
		if scheme.Verbose {
			fmt.Println("Verification failed: e(CommitRootSecretG2, h) does not equal e(g1, Ciphertext.C0)")
		}
		return fmt.Errorf("e(CommitRootSecretG2, h) does not equal e(g1, Ciphertext.C0)")
	}

	return nil
}

func (scheme *BSW07S) verifyLeafNodes(ciphertext *models.Ciphertext, pk *models.PublicKey, root *models.Node, i *int) error {
	if root == nil {
		return nil
	}

	if root.Type == LeafNodeType {
		// e(Hash(attri), C[i]) = e(C', g2)
		hashG1, err := scheme.hashToG1([]byte(root.Attribute))
		if err != nil {
			return fmt.Errorf("failed to hash attribute %s: %w", root.Attribute, err)
		}

		left := bn256.Pair(hashG1, ciphertext.C[*i].C1)
		right := bn256.Pair(ciphertext.C[*i].C2, pk.G2)
		if !utilities.CompareGTByString(left, right) {
			return fmt.Errorf("e(Hash(%s), C[%d]) does not equal e(C', g2)", root.Attribute, *i)
		}
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

func (scheme *BSW07S) verifyInnerNodes(ciphertext *models.Ciphertext, pk *models.PublicKey, proof *models.CiphertextProof, root *models.Node, i *int) (*bn256.G2, error) {
	if root == nil {
		return nil, nil
	}

	if root.Type == LeafNodeType {
		return root.LeafCipher.CommitShareSecretG2, nil
	}

	// C(child_u) = C(u) x (EggCommitAllPolynomial[i]^[index(u)^i]
	E := proof.CommitAllPolynomialG2[*i]
	c := proof.CommitShareSecretInnerNodesG2[*i]
	E[0] = c
	*i++

	for _, child := range root.Children {
		c_child, err := scheme.verifyInnerNodes(ciphertext, pk, proof, child, i)
		if err != nil {
			return nil, err
		}

		left := calcPolynomialCommitment(E, child.Index)
		if !utilities.CompareG2ByString(left, c_child) {
			return nil, fmt.Errorf("secret commitment wrong for child node with index %d", child.Index)
		}
	}

	return c, nil
}

func calcPolynomialCommitment(E []*bn256.G2, idx int) *bn256.G2 {
	deg := len(E) - 1

	result := new(bn256.G2)

	idxPower := big.NewInt(1)
	idxBig := big.NewInt(int64(idx))

	for i := 0; i <= deg; i++ {
		temp := new(bn256.G2)
		temp.ScalarMult(E[i], idxPower)

		// result = result + E[i] * idx^i
		result.Add(result, temp)

		if i < deg {
			idxPower.Mul(idxPower, idxBig)
		}
	}

	return result
}
