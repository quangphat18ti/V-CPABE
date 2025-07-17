package VABE

type VABESchemeDemo interface {
	Setup(setupParams SetupParams) (SetupParams, error)
	KeyGen(keyGenParams KeyGenParams) (KeyGenResponse, error)
	Encrypt(encryptParams EncryptParams) (EncryptResponse, error)
	Decrypt(decryptParams DecryptParams) (DecryptResponse, error)
}
