package models

import (
	. "cpabe-prototype/VABE/access-policy"
	"encoding/json"
	"fmt"
	"github.com/cloudflare/bn256"
	"math/big"
	"os"
)

// Utility functions for file I/O

func SaveToFile(filename string, data interface{}) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func LoadFromFile(filename string, data interface{}) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	return decoder.Decode(data)
}

// Serializable versions of the original structs
type SerializablePublicKey struct {
	G1       []byte `json:"g1"`
	G2       []byte `json:"g2"`
	H        []byte `json:"h"`
	EggAlpha []byte `json:"egg_alpha"`
}

type SerializableMasterSecretKey struct {
	Beta    []byte `json:"beta"`
	G1Alpha []byte `json:"g1_alpha"`
}

type SerializableAttributeKey struct {
	K1 []byte `json:"k1"`
	K2 []byte `json:"k2"`
}

type SerializableSecretKey struct {
	AttrList []string                             `json:"attr_list"`
	K0       []byte                               `json:"k0"`
	K        map[string]*SerializableAttributeKey `json:"k"`
}

type SerializableSecretKeyProof struct {
	V []byte `json:"v"`
}

type SerializableAttributeCiphertext struct {
	C1 []byte `json:"c1"`
	C2 []byte `json:"c2"`
}

type SerializableCiphertext struct {
	EncryptedData []byte                             `json:"encrypted_data"`
	RandGT        []byte                             `json:"rand_gt"`
	Policy        AccessPolicy                       `json:"policy"`
	C0            []byte                             `json:"c0"`
	CM            []byte                             `json:"cm"`
	C             []*SerializableAttributeCiphertext `json:"c"`
}

type SerializableCiphertextProof struct {
	CommitRootSecretG1            []byte   `json:"commit_root_secret_g1"`
	CommitShareSecretInnerNodesG2 [][]byte `json:"commit_share_secret_inner_nodes_g2"`
	CommitAllPolynomialG2         [][]byte `json:"commit_all_polynomial_g2"`
}

type SerializableVerificationParams struct {
	KeyProof        *SerializableSecretKeyProof  `json:"key_proof"`
	CiphertextProof *SerializableCiphertextProof `json:"ciphertext_proof"`
}

// Conversion functions: Original -> Serializable

func (pk *PublicKey) ToSerializable() *SerializablePublicKey {
	return &SerializablePublicKey{
		G1:       pk.G1.Marshal(),
		G2:       pk.G2.Marshal(),
		H:        pk.H.Marshal(),
		EggAlpha: pk.EggAlpha.Marshal(),
	}
}

func (msk *MasterSecretKey) ToSerializable() *SerializableMasterSecretKey {
	return &SerializableMasterSecretKey{
		Beta:    msk.Beta.Bytes(),
		G1Alpha: msk.G1Alpha.Marshal(),
	}
}

func (ak *AttributeKey) ToSerializable() *SerializableAttributeKey {
	return &SerializableAttributeKey{
		K1: ak.K1.Marshal(),
		K2: ak.K2.Marshal(),
	}
}

func (sk *SecretKey) ToSerializable() *SerializableSecretKey {
	serialK := make(map[string]*SerializableAttributeKey)
	for attr, attrKey := range sk.K {
		serialK[attr] = attrKey.ToSerializable()
	}

	return &SerializableSecretKey{
		AttrList: sk.AttrList,
		K0:       sk.K0.Marshal(),
		K:        serialK,
	}
}

func (skp *SecretKeyProof) ToSerializable() *SerializableSecretKeyProof {
	return &SerializableSecretKeyProof{
		V: skp.V.Marshal(),
	}
}

func (ac *AttributeCiphertext) ToSerializable() *SerializableAttributeCiphertext {
	return &SerializableAttributeCiphertext{
		C1: ac.C1.Marshal(),
		C2: ac.C2.Marshal(),
	}
}

func (ct *Ciphertext) ToSerializable() *SerializableCiphertext {
	serialC := make([]*SerializableAttributeCiphertext, len(ct.C))
	for i, attrCt := range ct.C {
		serialC[i] = attrCt.ToSerializable()
	}

	return &SerializableCiphertext{
		RandGT:        ct.RandGT.Marshal(),
		EncryptedData: ct.EncryptedData,
		Policy:        ct.Policy,
		C0:            ct.C0.Marshal(),
		CM:            ct.CM.Marshal(),
		C:             serialC,
	}
}

func (cp *CiphertextProof) ToSerializable() *SerializableCiphertextProof {
	// Convert CommitShareSecretInnerNodesG2
	commitShareSecret := make([][]byte, len(cp.CommitShareSecretInnerNodesG2))
	for i, commit := range cp.CommitShareSecretInnerNodesG2 {
		commitShareSecret[i] = commit.Marshal()
	}

	// Convert CommitAllPolynomialG2 (2D slice)
	commitAllPoly := make([][]byte, 0)
	for _, polyGroup := range cp.CommitAllPolynomialG2 {
		for _, poly := range polyGroup {
			commitAllPoly = append(commitAllPoly, poly.Marshal())
		}
	}

	return &SerializableCiphertextProof{
		CommitRootSecretG1:            cp.CommitRootSecretG1.Marshal(),
		CommitShareSecretInnerNodesG2: commitShareSecret,
		CommitAllPolynomialG2:         commitAllPoly,
	}
}

func (vp *VerificationParams) ToSerializable() *SerializableVerificationParams {
	var keyProof *SerializableSecretKeyProof
	var ciphertextProof *SerializableCiphertextProof

	if vp.KeyProof != nil {
		keyProof = vp.KeyProof.ToSerializable()
	}

	if vp.CiphertextProof != nil {
		ciphertextProof = vp.CiphertextProof.ToSerializable()
	}

	return &SerializableVerificationParams{
		KeyProof:        keyProof,
		CiphertextProof: ciphertextProof,
	}
}

// Conversion functions: Serializable -> Original

func (spk *SerializablePublicKey) ToOriginal() (*PublicKey, error) {
	pk := &PublicKey{}

	// Unmarshal G1
	pk.G1 = new(bn256.G1)
	if _, err := pk.G1.Unmarshal(spk.G1); err != nil {
		return nil, err
	}

	// Unmarshal G2
	pk.G2 = new(bn256.G2)
	if _, err := pk.G2.Unmarshal(spk.G2); err != nil {
		return nil, err
	}

	// Unmarshal H
	pk.H = new(bn256.G2)
	if _, err := pk.H.Unmarshal(spk.H); err != nil {
		return nil, err
	}

	// Unmarshal EggAlpha
	pk.EggAlpha = new(bn256.GT)
	if _, err := pk.EggAlpha.Unmarshal(spk.EggAlpha); err != nil {
		return nil, err
	}

	return pk, nil
}

func (smsk *SerializableMasterSecretKey) ToOriginal() (*MasterSecretKey, error) {
	msk := &MasterSecretKey{}

	// Convert Beta
	msk.Beta = new(big.Int).SetBytes(smsk.Beta)

	// Unmarshal G1Alpha
	msk.G1Alpha = new(bn256.G1)
	if _, err := msk.G1Alpha.Unmarshal(smsk.G1Alpha); err != nil {
		return nil, err
	}

	return msk, nil
}

func (sak *SerializableAttributeKey) ToOriginal() (*AttributeKey, error) {
	ak := &AttributeKey{}

	// Unmarshal K1
	ak.K1 = new(bn256.G1)
	if _, err := ak.K1.Unmarshal(sak.K1); err != nil {
		return nil, err
	}

	// Unmarshal K2
	ak.K2 = new(bn256.G2)
	if _, err := ak.K2.Unmarshal(sak.K2); err != nil {
		return nil, err
	}

	return ak, nil
}

func (ssk *SerializableSecretKey) ToOriginal() (*SecretKey, error) {
	sk := &SecretKey{}

	// Copy AttrList
	sk.AttrList = ssk.AttrList

	// Unmarshal K0
	sk.K0 = new(bn256.G1)
	if _, err := sk.K0.Unmarshal(ssk.K0); err != nil {
		return nil, err
	}

	// Convert K map
	sk.K = make(map[string]*AttributeKey)
	for attr, serialAttrKey := range ssk.K {
		attrKey, err := serialAttrKey.ToOriginal()
		if err != nil {
			return nil, err
		}
		sk.K[attr] = attrKey
	}

	return sk, nil
}

func (sskp *SerializableSecretKeyProof) ToOriginal() (*SecretKeyProof, error) {
	skp := &SecretKeyProof{}

	// Unmarshal V
	skp.V = new(bn256.GT)
	if _, err := skp.V.Unmarshal(sskp.V); err != nil {
		return nil, err
	}

	return skp, nil
}

func (sac *SerializableAttributeCiphertext) ToOriginal() (*AttributeCiphertext, error) {
	ac := &AttributeCiphertext{}

	// Unmarshal C1
	ac.C1 = new(bn256.G2)
	if _, err := ac.C1.Unmarshal(sac.C1); err != nil {
		return nil, err
	}

	// Unmarshal C2
	ac.C2 = new(bn256.G1)
	if _, err := ac.C2.Unmarshal(sac.C2); err != nil {
		return nil, err
	}

	return ac, nil
}

func (sct *SerializableCiphertext) ToOriginal() (*Ciphertext, error) {
	ct := &Ciphertext{}

	// copy Encrypted Content
	ct.EncryptedData = sct.EncryptedData

	// Copy Policy
	ct.Policy = sct.Policy

	// Unmarshal C0
	ct.C0 = new(bn256.G2)
	if _, err := ct.C0.Unmarshal(sct.C0); err != nil {
		return nil, err
	}

	// Unmarshal CM
	ct.CM = new(bn256.GT)
	if _, err := ct.CM.Unmarshal(sct.CM); err != nil {
		return nil, err
	}

	// Convert C slice
	ct.C = make([]*AttributeCiphertext, len(sct.C))
	for i, serialAttrCt := range sct.C {
		attrCt, err := serialAttrCt.ToOriginal()
		if err != nil {
			return nil, err
		}
		ct.C[i] = attrCt
	}

	return ct, nil
}

func (scp *SerializableCiphertextProof) ToOriginal() (*CiphertextProof, error) {
	cp := &CiphertextProof{}

	// Unmarshal CommitRootSecretG1
	cp.CommitRootSecretG1 = new(bn256.G1)
	if _, err := cp.CommitRootSecretG1.Unmarshal(scp.CommitRootSecretG1); err != nil {
		return nil, err
	}

	// Unmarshal CommitShareSecretInnerNodesG2
	cp.CommitShareSecretInnerNodesG2 = make([]*bn256.G2, len(scp.CommitShareSecretInnerNodesG2))
	for i, commitData := range scp.CommitShareSecretInnerNodesG2 {
		cp.CommitShareSecretInnerNodesG2[i] = new(bn256.G2)
		if _, err := cp.CommitShareSecretInnerNodesG2[i].Unmarshal(commitData); err != nil {
			return nil, err
		}
	}

	// Note: CommitAllPolynomialG2 reconstruction depends on your specific structure
	// This is a simplified version - you might need to adjust based on your actual 2D structure
	cp.CommitAllPolynomialG2 = make([][]*bn256.G2, 1)
	cp.CommitAllPolynomialG2[0] = make([]*bn256.G2, len(scp.CommitAllPolynomialG2))
	for i, polyData := range scp.CommitAllPolynomialG2 {
		cp.CommitAllPolynomialG2[0][i] = new(bn256.G2)
		if _, err := cp.CommitAllPolynomialG2[0][i].Unmarshal(polyData); err != nil {
			return nil, err
		}
	}

	return cp, nil
}

func (svp *SerializableVerificationParams) ToOriginal() (*VerificationParams, error) {
	vp := &VerificationParams{}

	// Convert KeyProof
	if svp.KeyProof != nil {
		keyProof, err := svp.KeyProof.ToOriginal()
		if err != nil {
			return nil, err
		}
		vp.KeyProof = keyProof
	}

	// Convert CiphertextProof
	if svp.CiphertextProof != nil {
		ciphertextProof, err := svp.CiphertextProof.ToOriginal()
		if err != nil {
			return nil, err
		}
		vp.CiphertextProof = ciphertextProof
	}

	return vp, nil
}

// Convenience functions for common operations

func SavePublicKey(filename string, pk *PublicKey) error {
	return SaveToFile(filename, pk.ToSerializable())
}

func LoadPublicKey(filename string) (*PublicKey, error) {
	var spk SerializablePublicKey
	if err := LoadFromFile(filename, &spk); err != nil {
		return nil, err
	}
	return spk.ToOriginal()
}

func SaveMasterSecretKey(filename string, msk *MasterSecretKey) error {
	return SaveToFile(filename, msk.ToSerializable())
}

func LoadMasterSecretKey(filename string) (*MasterSecretKey, error) {
	var smsk SerializableMasterSecretKey
	if err := LoadFromFile(filename, &smsk); err != nil {
		return nil, err
	}
	return smsk.ToOriginal()
}

func SaveSecretKey(filename string, sk *SecretKey) error {
	return SaveToFile(filename, sk.ToSerializable())
}

func LoadSecretKey(filename string) (*SecretKey, error) {
	var ssk SerializableSecretKey
	if err := LoadFromFile(filename, &ssk); err != nil {
		return nil, err
	}
	return ssk.ToOriginal()
}

func SavePrivateKeyProof(filename string, skp *SecretKeyProof) error {
	return SaveToFile(filename, skp.ToSerializable())
}

func LoadPrivateKeyProof(filename string) (*SecretKeyProof, error) {
	var sskp SerializableSecretKeyProof
	if err := LoadFromFile(filename, &sskp); err != nil {
		return nil, err
	}
	return sskp.ToOriginal()
}

func SaveCiphertext(filename string, ct *Ciphertext) error {
	return SaveToFile(filename, ct.ToSerializable())
}

func LoadCiphertext(filename string) (*Ciphertext, error) {
	var sct SerializableCiphertext
	if err := LoadFromFile(filename, &sct); err != nil {
		return nil, err
	}
	return sct.ToOriginal()
}

func SaveCiphertextProof(filename string, ctp *CiphertextProof) error {
	return SaveToFile(filename, ctp.ToSerializable())
}

func LoadCiphertextProof(filename string) (*CiphertextProof, error) {
	var scp SerializableCiphertextProof
	if err := LoadFromFile(filename, &scp); err != nil {
		return nil, err
	}
	return scp.ToOriginal()
}

func SaveVerificationParams(filename string, vp *VerificationParams) error {
	return SaveToFile(filename, vp.ToSerializable())
}

func LoadVerificationParams(filename string) (*VerificationParams, error) {
	var svp SerializableVerificationParams
	if err := LoadFromFile(filename, &svp); err != nil {
		return nil, err
	}
	return svp.ToOriginal()
}

func LoadAttributes(filename string) ([]string, error) {
	var attrs []string
	if err := LoadFromFile(filename, &attrs); err != nil {
		return nil, err
	}
	return attrs, nil
}

func SaveAttributes(filename string, attrs []string) error {
	return SaveToFile(filename, attrs)
}

func LoadAccessPolicy(filename string) (*AccessPolicy, error) {
	var sap SerializableAccessPolicy
	if err := LoadFromFile(filename, &sap); err != nil {
		return nil, err
	}
	return sap.ToOriginal(), nil
}

func SaveAccessPolicy(filename string, ap *AccessPolicy) error {
	return SaveToFile(filename, ap.ToSerializable())
}

func LoadPlainFile(filename string) ([]byte, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func SaveDecryptFile(filename string, data []byte) error {
	return os.WriteFile(filename, data, 0644)
}

type SerializableNode struct {
	Type        NodeType                 `json:"type"`
	Attribute   string                   `json:"attribute"`
	Index       int                      `json:"index"`
	Secrete     []byte                   `json:"secrete,omitempty"`
	Children    []*SerializableNode      `json:"children,omitempty"`
	Polynomial  []string                 `json:"polynomial,omitempty"` // Big.Int as strings
	Threshold   int                      `json:"threshold"`
	IsLeaf      bool                     `json:"is_leaf"`
	InnerCipher *SerializableInnerCipher `json:"inner_cipher,omitempty"`
	LeafCipher  *SerializableLeafCipher  `json:"leaf_cipher,omitempty"`
}

type SerializableInnerCipher struct {
	CommitShareSecretG2     []byte   `json:"commit_share_secret_g2"`
	CommitPolynomialCoeffG2 [][]byte `json:"commit_polynomial_coeff_g2"`
}

type SerializableLeafCipher struct {
	CommitShareSecretG2  []byte `json:"commit_share_secret_g2"`
	HashPowShareSecretG1 []byte `json:"hash_pow_share_secret_g1"`
}

// ToSerializable converts a Node to its serializable version
func (n *Node) ToSerializable() *SerializableNode {
	if n == nil {
		return nil
	}

	sn := &SerializableNode{
		Type:      n.Type,
		Attribute: n.Attribute,
		Index:     n.Index,
		Threshold: n.Threshold,
		IsLeaf:    n.IsLeaf,
	}

	// Convert Secrete
	secreteInt := big.Int(n.Secrete)
	sn.Secrete = secreteInt.Bytes()

	// Convert Children
	if len(n.Children) > 0 {
		sn.Children = make([]*SerializableNode, len(n.Children))
		for i, child := range n.Children {
			sn.Children[i] = child.ToSerializable()
		}
	}

	// Convert Polynomial
	if len(n.Polynomial) > 0 {
		sn.Polynomial = make([]string, len(n.Polynomial))
		for i, p := range n.Polynomial {
			sn.Polynomial[i] = p.String()
		}
	}

	// Convert InnerCipher
	if n.InnerCipher != nil {
		sn.InnerCipher = &SerializableInnerCipher{
			CommitShareSecretG2: n.InnerCipher.CommitShareSecretG2.Marshal(),
		}

		if len(n.InnerCipher.CommitPolynomialCoeffG2) > 0 {
			sn.InnerCipher.CommitPolynomialCoeffG2 = make([][]byte, len(n.InnerCipher.CommitPolynomialCoeffG2))
			for i, c := range n.InnerCipher.CommitPolynomialCoeffG2 {
				sn.InnerCipher.CommitPolynomialCoeffG2[i] = c.Marshal()
			}
		}
	}

	// Convert LeafCipher
	if n.LeafCipher != nil {
		sn.LeafCipher = &SerializableLeafCipher{
			CommitShareSecretG2:  n.LeafCipher.CommitShareSecretG2.Marshal(),
			HashPowShareSecretG1: n.LeafCipher.HashPowShareSecretG1.Marshal(),
		}
	}

	return sn
}

// ToOriginal converts a SerializableNode back to a Node
func (sn *SerializableNode) ToOriginal() (*Node, error) {
	if sn == nil {
		return nil, nil
	}

	n := &Node{
		Type:      sn.Type,
		Attribute: sn.Attribute,
		Index:     sn.Index,
		Threshold: sn.Threshold,
		IsLeaf:    sn.IsLeaf,
	}

	// Convert Secrete
	if sn.Secrete != nil {
		secreteInt := new(big.Int).SetBytes(sn.Secrete)
		n.Secrete = Secrete(*secreteInt)
	}

	// Convert Children
	if len(sn.Children) > 0 {
		n.Children = make([]*Node, len(sn.Children))
		for i, child := range sn.Children {
			var err error
			n.Children[i], err = child.ToOriginal()
			if err != nil {
				return nil, err
			}
		}
	}

	// Convert Polynomial
	if len(sn.Polynomial) > 0 {
		n.Polynomial = make([]big.Int, len(sn.Polynomial))
		for i, p := range sn.Polynomial {
			if _, ok := n.Polynomial[i].SetString(p, 10); !ok {
				return nil, fmt.Errorf("failed to parse polynomial coefficient: %s", p)
			}
		}
	}

	// Convert InnerCipher
	if sn.InnerCipher != nil {
		n.InnerCipher = &InnerNodeCiphertext{
			CommitShareSecretG2: new(bn256.G2),
		}

		if _, err := n.InnerCipher.CommitShareSecretG2.Unmarshal(sn.InnerCipher.CommitShareSecretG2); err != nil {
			return nil, err
		}

		if len(sn.InnerCipher.CommitPolynomialCoeffG2) > 0 {
			n.InnerCipher.CommitPolynomialCoeffG2 = make([]*bn256.G2, len(sn.InnerCipher.CommitPolynomialCoeffG2))
			for i, c := range sn.InnerCipher.CommitPolynomialCoeffG2 {
				n.InnerCipher.CommitPolynomialCoeffG2[i] = new(bn256.G2)
				if _, err := n.InnerCipher.CommitPolynomialCoeffG2[i].Unmarshal(c); err != nil {
					return nil, err
				}
			}
		}
	}

	// Convert LeafCipher
	if sn.LeafCipher != nil {
		n.LeafCipher = &LeafNodeCiphertext{
			CommitShareSecretG2:  new(bn256.G2),
			HashPowShareSecretG1: new(bn256.G1),
		}

		if _, err := n.LeafCipher.CommitShareSecretG2.Unmarshal(sn.LeafCipher.CommitShareSecretG2); err != nil {
			return nil, err
		}

		if _, err := n.LeafCipher.HashPowShareSecretG1.Unmarshal(sn.LeafCipher.HashPowShareSecretG1); err != nil {
			return nil, err
		}
	}

	return n, nil
}

// SaveAccessTree saves an AccessTree to a file
func SaveAccessTree(filename string, tree AccessTree) error {
	serializable := tree.ToSerializable()
	return SaveToFile(filename, serializable)
}

// LoadAccessTree loads an AccessTree from a file
func LoadAccessTree(filename string) (AccessTree, error) {
	var sn SerializableNode
	if err := LoadFromFile(filename, &sn); err != nil {
		return nil, err
	}
	return sn.ToOriginal()
}
