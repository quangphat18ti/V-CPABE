package models

import (
	. "cpabe-prototype/VABE/access-policy"
	"cpabe-prototype/pkg/utilities"
	"fmt"
	"github.com/cloudflare/bn256"
	"math/big"
	"os"
	"slices"
)

// Serializable versions of the original structs
type SerializablePublicKey struct {
	G1       []byte `json:"g1"`
	G2       []byte `json:"g2"`
	G1A      []byte `json:"g1a"`
	EggAlpha []byte `json:"egg_alpha"`
}

type SerializableMasterSecretKey struct {
	Alpha []byte `json:"alpha"`
	G2A   []byte `json:"g2_a"`
}

type SerializableAttributeKey struct {
	K1 []byte `json:"k1"`
}

type SerializableSecretKey struct {
	AttrList []string                             `json:"attr_list"`
	K0       []byte                               `json:"k0"`
	L        []byte                               `json:"l"` // L = g2^t
	K        map[string]*SerializableAttributeKey `json:"k"`
}

type SerializableSecretKeyProof struct{}

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
	CommitRootSecretG2     []byte                             `json:"commit_root_secret_g2"`
	InnerNodeCiphertexts   []*SerializableAttributeCiphertext `json:"inner_node_ciphertexts"`
	EggCommitAllPolynomial [][]byte                           `json:"egg_commit_all_polynomial"`
	EggASecret             []byte                             `json:"egg_a_secret"`
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
		G1A:      pk.G1A.Marshal(),
		EggAlpha: pk.EggAlpha.Marshal(),
	}
}

func (msk *MasterSecretKey) ToSerializable() *SerializableMasterSecretKey {
	return &SerializableMasterSecretKey{
		Alpha: msk.Alpha.Bytes(),
		G2A:   msk.G2A.Marshal(),
	}
}

func (ak *AttributeKey) ToSerializable() *SerializableAttributeKey {
	return &SerializableAttributeKey{
		K1: ak.K1.Marshal(),
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
		L:        sk.L.Marshal(),
		K:        serialK,
	}
}

func (skp *SecretKeyProof) ToSerializable() *SerializableSecretKeyProof {
	return &SerializableSecretKeyProof{}
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
		//RandGT:        ct.RandGT.Marshal(),
		EncryptedData: ct.EncryptedData,
		Policy:        ct.Policy,
		C0:            ct.C0.Marshal(),
		CM:            ct.CM.Marshal(),
		C:             serialC,
	}
}

func (cp *CiphertextProof) ToSerializable() *SerializableCiphertextProof {
	// Convert InnerNodeCiphertexts
	serialC := make([]*SerializableAttributeCiphertext, len(cp.InnerNodeCiphertexts))
	for i, attrCt := range cp.InnerNodeCiphertexts {
		serialC[i] = attrCt.ToSerializable()
	}

	// Convert EggCommitAllPolynomial (2D slice)
	commitAllPoly := make([][]byte, 0)
	for _, polyGroup := range cp.EggCommitAllPolynomial {
		polyBytes := make([]byte, 0)
		for _, poly := range polyGroup {
			polyBytes = slices.Concat(polyBytes, poly.Marshal())
		}
		commitAllPoly = append(commitAllPoly, polyBytes)
	}

	return &SerializableCiphertextProof{
		CommitRootSecretG2:     cp.CommitRootSecretG2.Marshal(),
		InnerNodeCiphertexts:   serialC,
		EggCommitAllPolynomial: commitAllPoly,
		EggASecret:             cp.EggASecret.Marshal(),
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

	// Unmarshal G1A
	pk.G1A = new(bn256.G1)
	if _, err := pk.G1A.Unmarshal(spk.G1A); err != nil {
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

	// Convert Alpha
	msk.Alpha = new(big.Int).SetBytes(smsk.Alpha)

	// Unmarshal G2A
	msk.G2A = new(bn256.G2)
	if _, err := msk.G2A.Unmarshal(smsk.G2A); err != nil {
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

	return ak, nil
}

func (ssk *SerializableSecretKey) ToOriginal() (*SecretKey, error) {
	sk := &SecretKey{}

	// Copy AttrList
	sk.AttrList = ssk.AttrList

	// Unmarshal K0
	sk.K0 = new(bn256.G2)
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

	// Convert L
	sk.L = new(bn256.G2)
	if _, err := sk.L.Unmarshal(ssk.L); err != nil {
		return nil, err
	}

	return sk, nil
}

func (sskp *SerializableSecretKeyProof) ToOriginal() (*SecretKeyProof, error) {
	skp := &SecretKeyProof{}
	return skp, nil
}

func (sac *SerializableAttributeCiphertext) ToOriginal() (*AttributeCiphertext, error) {
	ac := &AttributeCiphertext{}

	// Unmarshal C1
	ac.C1 = new(bn256.G1)
	if _, err := ac.C1.Unmarshal(sac.C1); err != nil {
		return nil, err
	}

	// Unmarshal C2
	ac.C2 = new(bn256.G2)
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
	ct.C0 = new(bn256.G1)
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

	// Unmarshal CommitRootSecretG2
	cp.CommitRootSecretG2 = new(bn256.G2)
	if _, err := cp.CommitRootSecretG2.Unmarshal(scp.CommitRootSecretG2); err != nil {
		return nil, err
	}

	// Unmarshal InnerNodeCiphertexts
	cp.InnerNodeCiphertexts = make([]AttributeCiphertext, len(scp.InnerNodeCiphertexts))
	for i, commitData := range scp.InnerNodeCiphertexts {
		cp.InnerNodeCiphertexts[i] = AttributeCiphertext{}
		origin, err := commitData.ToOriginal()
		if err != nil {
			return nil, fmt.Errorf("failed to convert InnerNodeCiphertexts[%d]: %v", i, err)
		}
		cp.InnerNodeCiphertexts[i] = *origin
	}

	// Note: EggCommitAllPolynomial reconstruction depends on your specific structure
	// This is a simplified version - you might need to adjust based on your actual 2D structure

	// Each value is a 256-bit number.
	//const numBytes = 256 / 8 * 4 // 256 bits = 32 bytes, 4 values = 128 bytes
	//const eachPointSize = (256/8)*4 + 1
	var eachPointSize int = len(new(bn256.GT).Marshal())

	numGroups := len(scp.EggCommitAllPolynomial)
	cp.EggCommitAllPolynomial = make([][]*bn256.GT, numGroups)
	for i := 0; i < numGroups; i++ {
		elementOfGroups := len(scp.EggCommitAllPolynomial[i]) / eachPointSize // Assuming each group has 32 elements
		cp.EggCommitAllPolynomial[i] = make([]*bn256.GT, elementOfGroups)
		for j := 0; j < elementOfGroups; j++ {
			cp.EggCommitAllPolynomial[i][j] = new(bn256.GT)
			start := j * eachPointSize
			end := start + eachPointSize
			bytes := scp.EggCommitAllPolynomial[i][start:end]
			if _, err := cp.EggCommitAllPolynomial[i][j].Unmarshal(bytes); err != nil {
				return nil, fmt.Errorf("failed to unmarshal EggCommitAllPolynomial[%d][%d]: %v", i, j, err)
			}
		}
	}

	// Unmarshal EggASecret
	cp.EggASecret = new(bn256.GT)
	if _, err := cp.EggASecret.Unmarshal(scp.EggASecret); err != nil {
		return nil, err
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
	return utilities.SaveToFile(filename, pk.ToSerializable())
}

func LoadPublicKey(filename string) (*PublicKey, error) {
	var spk SerializablePublicKey
	if err := utilities.LoadFromFile(filename, &spk); err != nil {
		return nil, err
	}
	return spk.ToOriginal()
}

func SaveMasterSecretKey(filename string, msk *MasterSecretKey) error {
	return utilities.SaveToFile(filename, msk.ToSerializable())
}

func LoadMasterSecretKey(filename string) (*MasterSecretKey, error) {
	var smsk SerializableMasterSecretKey
	if err := utilities.LoadFromFile(filename, &smsk); err != nil {
		return nil, err
	}
	return smsk.ToOriginal()
}

func SaveSecretKey(filename string, sk *SecretKey) error {
	return utilities.SaveToFile(filename, sk.ToSerializable())
}

func LoadSecretKey(filename string) (*SecretKey, error) {
	var ssk SerializableSecretKey
	if err := utilities.LoadFromFile(filename, &ssk); err != nil {
		return nil, err
	}
	return ssk.ToOriginal()
}

func SaveSecretKeyProof(filename string, skp *SecretKeyProof) error {
	return utilities.SaveToFile(filename, skp.ToSerializable())
}

func LoadSecretKeyProof(filename string) (*SecretKeyProof, error) {
	var sskp SerializableSecretKeyProof
	if err := utilities.LoadFromFile(filename, &sskp); err != nil {
		return nil, err
	}
	return sskp.ToOriginal()
}

func SaveCiphertext(filename string, ct *Ciphertext) error {
	return utilities.SaveToFile(filename, ct.ToSerializable())
}

func LoadCiphertext(filename string) (*Ciphertext, error) {
	var sct SerializableCiphertext
	if err := utilities.LoadFromFile(filename, &sct); err != nil {
		return nil, err
	}
	return sct.ToOriginal()
}

func SaveCiphertextProof(filename string, ctp *CiphertextProof) error {
	return utilities.SaveToFile(filename, ctp.ToSerializable())
}

func LoadCiphertextProof(filename string) (*CiphertextProof, error) {
	var scp SerializableCiphertextProof
	if err := utilities.LoadFromFile(filename, &scp); err != nil {
		return nil, err
	}
	return scp.ToOriginal()
}

func SaveVerificationParams(filename string, vp *VerificationParams) error {
	return utilities.SaveToFile(filename, vp.ToSerializable())
}

func LoadVerificationParams(filename string) (*VerificationParams, error) {
	var svp SerializableVerificationParams
	if err := utilities.LoadFromFile(filename, &svp); err != nil {
		return nil, err
	}
	return svp.ToOriginal()
}

func LoadAttributes(filename string) ([]string, error) {
	var attrs []string
	if err := utilities.LoadFromFile(filename, &attrs); err != nil {
		return nil, err
	}
	return attrs, nil
}

func SaveAttributes(filename string, attrs []string) error {
	return utilities.SaveToFile(filename, attrs)
}

func LoadAccessPolicy(filename string) (*AccessPolicy, error) {
	var sap SerializableAccessPolicy
	if err := utilities.LoadFromFile(filename, &sap); err != nil {
		return nil, err
	}
	return sap.ToOriginal(), nil
}

func SaveAccessPolicy(filename string, ap *AccessPolicy) error {
	return utilities.SaveToFile(filename, ap.ToSerializable())
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
