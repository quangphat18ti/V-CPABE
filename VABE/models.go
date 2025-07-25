package VABE

type SetupParams struct {
	PublicKeyPath       string `default:"out/utils/public_key"`
	MasterSecretKeyPath string `default:"out/utils/master_secret_key"`
}

type KeyGenParams struct {
	PublicKeyPath       string `default:"out/utils/public_key"`
	MasterSecretKeyPath string `default:"out/utils/master_secret_key"`
	AttributePath       string `default:"in/utils/attributes"`
	UserPrivateKeyPath  string `default:"out/keys/private_key"`
	PrivateKeyProofPath string `default:"out/keys/key_proof"`
}

type KeyGenResponse struct {
	UserPrivateKeyPath  string `default:"out/keys/private_key"`
	PrivateKeyProofPath string `default:"out/keys/key_proof"`
}

type EncryptParams struct {
	PublicKeyPath       string `default:"out/utils/public_key"`
	AccessPolicyPath    string `default:"in/utils/access_policy"`
	InputFilePath       string `default:"in/files/input_file.txt"`
	CipherTextPath      string `default:"out/ciphertexts/ciphertext"`
	CipherTextProofPath string `default:"out/ciphertexts/ciphertext_proof"`
}

type EncryptResponse struct {
	CipherTextPath      string `default:"out/ciphertexts/ciphertext"`
	CipherTextProofPath string `default:"out/ciphertexts/ciphertext_proof"`
}

type DecryptParams struct {
	PublicKeyPath      string `default:"out/utils/public_key"`
	UserPrivateKeyPath string `default:"out/keys/private_key"`
	CipherTextPath     string `default:"out/ciphertexts/ciphertext"`
	DecryptedFilePath  string `default:"out/files/decrypted_file.txt"`
}

type DecryptResponse struct {
	DecryptedFilePath string `default:"out/files/decrypted_file.txt"`
}

type VerifyKeyParams struct {
	PublicKeyPath       string `default:"out/utils/public_key"`
	UserPrivateKeyPath  string `default:"out/keys/private_key"`
	PrivateKeyProofPath string `default:"out/keys/key_proof"`
	UserAttributesPath  string `default:"in/utils/attributes"`
}

type VerifyCiphertextParams struct {
	PublicKeyPath       string `default:"out/utils/public_key"`
	CipherTextPath      string `default:"out/ciphertexts/ciphertext"`
	CipherTextProofPath string `default:"out/ciphertexts/ciphertext_proof"`
	AccessPolicyPath    string `default:"in/utils/access_policy"`
}
