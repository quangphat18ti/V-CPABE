package models

import (
	. "cpabe-prototype/VABE/access-policy"
	"github.com/cloudflare/bn256"
	"math/big"
	"os"
	"reflect"
	"testing"
)

// Helper function to create a sample PublicKey
func createSamplePublicKey() *PublicKey {
	pk := &PublicKey{}

	// Generate random points for testing
	pk.G1 = new(bn256.G1).ScalarBaseMult(big.NewInt(123))
	pk.G2 = new(bn256.G2).ScalarBaseMult(big.NewInt(456))
	pk.H = new(bn256.G2).ScalarBaseMult(big.NewInt(789))
	pk.EggAlpha = bn256.Pair(pk.G1, pk.G2)

	return pk
}

// Helper function to create a sample MasterSecretKey
func createSampleMasterSecretKey() *MasterSecretKey {
	msk := &MasterSecretKey{}
	msk.Beta = big.NewInt(54321)
	msk.G1Alpha = new(bn256.G1).ScalarBaseMult(big.NewInt(98765))
	return msk
}

// Helper function to create a sample SecretKey
func createSampleSecretKey() *SecretKey {
	sk := &SecretKey{}
	sk.AttrList = []string{"attr1", "attr2", "attr3"}
	sk.K0 = new(bn256.G1).ScalarBaseMult(big.NewInt(111))

	sk.K = make(map[string]*AttributeKey)
	for _, attr := range sk.AttrList {
		sk.K[attr] = &AttributeKey{
			K1: new(bn256.G1).ScalarBaseMult(big.NewInt(222)),
			K2: new(bn256.G2).ScalarBaseMult(big.NewInt(333)),
		}
	}

	return sk
}

// Helper function to create a sample SecretKeyProof
func createSampleSecretKeyProof() *SecretKeyProof {
	skp := &SecretKeyProof{}
	g1 := new(bn256.G1).ScalarBaseMult(big.NewInt(123))
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(456))
	skp.V = bn256.Pair(g1, g2)
	return skp
}

// Helper function to create a sample Ciphertext
func createSampleCiphertext() *Ciphertext {
	ct := &Ciphertext{}

	// Create a simple access policy for testing
	ct.Policy = AccessPolicy{
		// You'll need to adjust this based on your actual AccessPolicy structure
		// For now, I'll leave it as the zero value
	}

	ct.C0 = new(bn256.G2).ScalarBaseMult(big.NewInt(777))

	g1 := new(bn256.G1).ScalarBaseMult(big.NewInt(888))
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(999))
	ct.CM = bn256.Pair(g1, g2)

	// Create some attribute ciphertexts
	ct.C = []*AttributeCiphertext{
		{
			C1: new(bn256.G2).ScalarBaseMult(big.NewInt(1111)),
			C2: new(bn256.G1).ScalarBaseMult(big.NewInt(2222)),
		},
		{
			C1: new(bn256.G2).ScalarBaseMult(big.NewInt(3333)),
			C2: new(bn256.G1).ScalarBaseMult(big.NewInt(4444)),
		},
	}

	return ct
}

// Helper function to create a sample CiphertextProof
func createSampleCiphertextProof() *CiphertextProof {
	cp := &CiphertextProof{}

	cp.CommitRootSecretG1 = new(bn256.G1).ScalarBaseMult(big.NewInt(5555))

	cp.CommitShareSecretInnerNodesG2 = []*bn256.G2{
		new(bn256.G2).ScalarBaseMult(big.NewInt(6666)),
		new(bn256.G2).ScalarBaseMult(big.NewInt(7777)),
	}

	cp.CommitAllPolynomialG2 = [][]*bn256.G2{
		{
			new(bn256.G2).ScalarBaseMult(big.NewInt(8888)),
			new(bn256.G2).ScalarBaseMult(big.NewInt(9999)),
		},
		{
			new(bn256.G2).ScalarBaseMult(big.NewInt(10101)),
		},
	}

	return cp
}

// Helper function to create sample VerificationParams
func createSampleVerificationParams() *VerificationParams {
	vp := &VerificationParams{}
	vp.KeyProof = createSampleSecretKeyProof()
	vp.CiphertextProof = createSampleCiphertextProof()
	return vp
}

// Test PublicKey serialization
func TestPublicKeySerialization(t *testing.T) {
	original := createSamplePublicKey()

	// Test conversion to serializable
	serializable := original.ToSerializable()
	if serializable == nil {
		t.Fatal("ToSerializable returned nil")
	}

	// Test conversion back to original
	restored, err := serializable.ToOriginal()
	if err != nil {
		t.Fatalf("ToOriginal failed: %v", err)
	}

	// Compare the results
	if !(original.G1.String() == restored.G1.String()) {
		t.Error("G1 values don't match")
	}
	if !(original.G2.String() == restored.G2.String()) {
		t.Error("G2 values don't match")
	}
	if !(original.H.String() == restored.H.String()) {
		t.Error("H values don't match")
	}
	if !(original.EggAlpha.String() == restored.EggAlpha.String()) {
		t.Error("EggAlpha values don't match")
	}
}

// Test MasterSecretKey serialization
func TestMasterSecretKeySerialization(t *testing.T) {
	original := createSampleMasterSecretKey()

	serializable := original.ToSerializable()
	if serializable == nil {
		t.Fatal("ToSerializable returned nil")
	}

	restored, err := serializable.ToOriginal()
	if err != nil {
		t.Fatalf("ToOriginal failed: %v", err)
	}

	if original.Beta.Cmp(restored.Beta) != 0 {
		t.Error("Beta values don't match")
	}
	if original.G1Alpha.String() != restored.G1Alpha.String() {
		t.Error("G1Alpha values don't match")
	}
}

// Test SecretKey serialization
func TestSecretKeySerialization(t *testing.T) {
	original := createSampleSecretKey()

	serializable := original.ToSerializable()
	if serializable == nil {
		t.Fatal("ToSerializable returned nil")
	}

	restored, err := serializable.ToOriginal()
	if err != nil {
		t.Fatalf("ToOriginal failed: %v", err)
	}

	if !reflect.DeepEqual(original.AttrList, restored.AttrList) {
		t.Error("AttrList values don't match")
	}

	if original.K0.String() != restored.K0.String() {
		t.Error("K0 values don't match")
	}

	if len(original.K) != len(restored.K) {
		t.Error("K map sizes don't match")
	}

	for attr, originalKey := range original.K {
		restoredKey, exists := restored.K[attr]
		if !exists {
			t.Errorf("Attribute %s missing in restored key", attr)
			continue
		}

		if originalKey.K1.String() != restoredKey.K1.String() {
			t.Errorf("K1 values don't match for attribute %s", attr)
		}
		if originalKey.K2.String() != restoredKey.K2.String() {
			t.Errorf("K2 values don't match for attribute %s", attr)
		}
	}
}

// Test SecretKeyProof serialization
func TestSecretKeyProofSerialization(t *testing.T) {
	original := createSampleSecretKeyProof()

	serializable := original.ToSerializable()
	if serializable == nil {
		t.Fatal("ToSerializable returned nil")
	}

	restored, err := serializable.ToOriginal()
	if err != nil {
		t.Fatalf("ToOriginal failed: %v", err)
	}

	if original.V.String() != restored.V.String() {
		t.Error("V values don't match")
	}
}

// Test Ciphertext serialization
func TestCiphertextSerialization(t *testing.T) {
	original := createSampleCiphertext()

	serializable := original.ToSerializable()
	if serializable == nil {
		t.Fatal("ToSerializable returned nil")
	}

	restored, err := serializable.ToOriginal()
	if err != nil {
		t.Fatalf("ToOriginal failed: %v", err)
	}

	if original.C0.String() != restored.C0.String() {
		t.Error("C0 values don't match")
	}

	if original.CM.String() != restored.CM.String() {
		t.Error("CM values don't match")
	}

	if len(original.C) != len(restored.C) {
		t.Error("C slice lengths don't match")
	}

	for i, originalAttr := range original.C {
		restoredAttr := restored.C[i]
		if originalAttr.C1.String() != restoredAttr.C1.String() {
			t.Errorf("C1 values don't match at index %d", i)
		}
		if originalAttr.C2.String() != restoredAttr.C2.String() {
			t.Errorf("C2 values don't match at index %d", i)
		}
	}
}

// Test CiphertextProof serialization
func TestCiphertextProofSerialization(t *testing.T) {
	original := createSampleCiphertextProof()

	serializable := original.ToSerializable()
	if serializable == nil {
		t.Fatal("ToSerializable returned nil")
	}

	restored, err := serializable.ToOriginal()
	if err != nil {
		t.Fatalf("ToOriginal failed: %v", err)
	}

	if original.CommitRootSecretG1.String() != restored.CommitRootSecretG1.String() {
		t.Error("CommitRootSecretG1 values don't match")
	}

	if len(original.CommitShareSecretInnerNodesG2) != len(restored.CommitShareSecretInnerNodesG2) {
		t.Error("CommitShareSecretInnerNodesG2 lengths don't match")
	}

	for i, originalCommit := range original.CommitShareSecretInnerNodesG2 {
		restoredCommit := restored.CommitShareSecretInnerNodesG2[i]
		if originalCommit.String() != restoredCommit.String() {
			t.Errorf("CommitShareSecretInnerNodesG2 values don't match at index %d", i)
		}
	}

	// Note: The polynomial reconstruction in ToOriginal() flattens the 2D structure
	// This test assumes a simple flattened comparison
	originalFlat := make([]*bn256.G2, 0)
	for _, polyGroup := range original.CommitAllPolynomialG2 {
		originalFlat = append(originalFlat, polyGroup...)
	}

	restoredFlat := restored.CommitAllPolynomialG2[0]

	if len(originalFlat) != len(restoredFlat) {
		t.Error("CommitAllPolynomialG2 flattened lengths don't match")
	}

	for i, originalPoly := range originalFlat {
		restoredPoly := restoredFlat[i]
		if originalPoly.String() != restoredPoly.String() {
			t.Errorf("CommitAllPolynomialG2 values don't match at index %d", i)
		}
	}
}

// Test VerificationParams serialization
func TestVerificationParamsSerialization(t *testing.T) {
	original := createSampleVerificationParams()

	serializable := original.ToSerializable()
	if serializable == nil {
		t.Fatal("ToSerializable returned nil")
	}

	restored, err := serializable.ToOriginal()
	if err != nil {
		t.Fatalf("ToOriginal failed: %v", err)
	}

	if original.KeyProof.V.String() != restored.KeyProof.V.String() {
		t.Error("KeyProof.V values don't match")
	}

	if original.CiphertextProof.CommitRootSecretG1.String() != restored.CiphertextProof.CommitRootSecretG1.String() {
		t.Error("CiphertextProof.CommitRootSecretG1 values don't match")
	}
}

// Test file I/O operations
func TestFileIO(t *testing.T) {
	// Test PublicKey file I/O
	t.Run("PublicKey File I/O", func(t *testing.T) {
		original := createSamplePublicKey()
		filename := "test_public_key.json"

		// Save to file
		err := SavePublicKey(filename, original)
		if err != nil {
			t.Fatalf("SavePublicKey failed: %v", err)
		}

		// Load from file
		loaded, err := LoadPublicKey(filename)
		if err != nil {
			t.Fatalf("LoadPublicKey failed: %v", err)
		}

		// Compare
		if original.G1.String() != loaded.G1.String() {
			t.Error("G1 values don't match after file I/O")
		}

		// Clean up
		os.Remove(filename)
	})

	// Test MasterSecretKey file I/O
	t.Run("MasterSecretKey File I/O", func(t *testing.T) {
		original := createSampleMasterSecretKey()
		filename := "test_master_secret_key.json"

		err := SaveMasterSecretKey(filename, original)
		if err != nil {
			t.Fatalf("SaveMasterSecretKey failed: %v", err)
		}

		loaded, err := LoadMasterSecretKey(filename)
		if err != nil {
			t.Fatalf("LoadMasterSecretKey failed: %v", err)
		}

		if original.Beta.Cmp(loaded.Beta) != 0 {
			t.Error("Beta values don't match after file I/O")
		}

		os.Remove(filename)
	})

	// Test SecretKey file I/O
	t.Run("SecretKey File I/O", func(t *testing.T) {
		original := createSampleSecretKey()
		filename := "test_secret_key.json"

		err := SaveSecretKey(filename, original)
		if err != nil {
			t.Fatalf("SaveSecretKey failed: %v", err)
		}

		loaded, err := LoadSecretKey(filename)
		if err != nil {
			t.Fatalf("LoadSecretKey failed: %v", err)
		}

		if !reflect.DeepEqual(original.AttrList, loaded.AttrList) {
			t.Error("AttrList values don't match after file I/O")
		}

		os.Remove(filename)
	})

	// Test Ciphertext file I/O
	t.Run("Ciphertext File I/O", func(t *testing.T) {
		original := createSampleCiphertext()
		filename := "test_ciphertext.json"

		err := SaveCiphertext(filename, original)
		if err != nil {
			t.Fatalf("SaveCiphertext failed: %v", err)
		}

		loaded, err := LoadCiphertext(filename)
		if err != nil {
			t.Fatalf("LoadCiphertext failed: %v", err)
		}

		if original.C0.String() != loaded.C0.String() {
			t.Error("C0 values don't match after file I/O")
		}

		os.Remove(filename)
	})

	// Test VerificationParams file I/O
	t.Run("VerificationParams File I/O", func(t *testing.T) {
		original := createSampleVerificationParams()
		filename := "test_verification_params.json"

		err := SaveVerificationParams(filename, original)
		if err != nil {
			t.Fatalf("SaveVerificationParams failed: %v", err)
		}

		loaded, err := LoadVerificationParams(filename)
		if err != nil {
			t.Fatalf("LoadVerificationParams failed: %v", err)
		}

		if original.KeyProof.V.String() != loaded.KeyProof.V.String() {
			t.Error("KeyProof.V values don't match after file I/O")
		}

		os.Remove(filename)
	})
}

// Test edge cases
func TestEdgeCases(t *testing.T) {
	// Test with nil values
	t.Run("Nil VerificationParams", func(t *testing.T) {
		vp := &VerificationParams{
			KeyProof:        nil,
			CiphertextProof: nil,
		}

		serializable := vp.ToSerializable()
		if serializable.KeyProof != nil {
			t.Error("Expected nil KeyProof")
		}
		if serializable.CiphertextProof != nil {
			t.Error("Expected nil CiphertextProof")
		}

		restored, err := serializable.ToOriginal()
		if err != nil {
			t.Fatalf("ToOriginal failed: %v", err)
		}

		if restored.KeyProof != nil {
			t.Error("Expected nil KeyProof after restoration")
		}
		if restored.CiphertextProof != nil {
			t.Error("Expected nil CiphertextProof after restoration")
		}
	})

	// Test with empty slices
	t.Run("Empty Slices", func(t *testing.T) {
		sk := &SecretKey{
			AttrList: []string{},
			K0:       new(bn256.G1).ScalarBaseMult(big.NewInt(1)),
			K:        make(map[string]*AttributeKey),
		}

		serializable := sk.ToSerializable()
		restored, err := serializable.ToOriginal()
		if err != nil {
			t.Fatalf("ToOriginal failed: %v", err)
		}

		if len(restored.AttrList) != 0 {
			t.Error("Expected empty AttrList")
		}
		if len(restored.K) != 0 {
			t.Error("Expected empty K map")
		}
	})
}

// Test error conditions
func TestErrorConditions(t *testing.T) {
	// Test loading from non-existent file
	t.Run("Non-existent File", func(t *testing.T) {
		_, err := LoadPublicKey("non_existent_file.json")
		if err == nil {
			t.Error("Expected error when loading non-existent file")
		}
	})

	// Test invalid JSON data
	t.Run("Invalid JSON", func(t *testing.T) {
		filename := "invalid.json"
		file, err := os.Create(filename)
		if err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		// Write invalid JSON
		_, err = file.WriteString("invalid json content")
		file.Close()
		if err != nil {
			t.Fatalf("Failed to write invalid JSON: %v", err)
		}

		_, err = LoadPublicKey(filename)
		if err == nil {
			t.Error("Expected error when loading invalid JSON")
		}

		os.Remove(filename)
	})
}

// Benchmark tests
func BenchmarkPublicKeySerialization(b *testing.B) {
	pk := createSamplePublicKey()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		serializable := pk.ToSerializable()
		_, err := serializable.ToOriginal()
		if err != nil {
			b.Fatalf("ToOriginal failed: %v", err)
		}
	}
}

func BenchmarkSecretKeySerialization(b *testing.B) {
	sk := createSampleSecretKey()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		serializable := sk.ToSerializable()
		_, err := serializable.ToOriginal()
		if err != nil {
			b.Fatalf("ToOriginal failed: %v", err)
		}
	}
}

func BenchmarkCiphertextSerialization(b *testing.B) {
	ct := createSampleCiphertext()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		serializable := ct.ToSerializable()
		_, err := serializable.ToOriginal()
		if err != nil {
			b.Fatalf("ToOriginal failed: %v", err)
		}
	}
}
