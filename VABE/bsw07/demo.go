package bsw07

import (
	"cpabe-prototype/VABE"
	"cpabe-prototype/VABE/bsw07/models"
	"fmt"
	"github.com/mcuadros/go-defaults"
)

type BSW07Demo struct {
	Verbose bool
	scheme  BSW07S
}

func (B BSW07Demo) Setup(setupParams VABE.SetupParams) (VABE.SetupParams, error) {
	defaults.SetDefaults(&setupParams)
	var err error

	publicKey, masterSecretKey, err := B.scheme.Setup()
	if err != nil {
		fmt.Println("Setup Error:", err)
		return setupParams, err
	}

	err = models.SavePublicKey(setupParams.PublicKeyPath, publicKey)
	if err != nil {
		fmt.Println("Error saving public key:", err)
		return setupParams, err
	}

	err = models.SaveMasterSecretKey(setupParams.MasterSecretKeyPath, masterSecretKey)
	if err != nil {
		fmt.Println("Error saving master secret key:", err)
		return setupParams, err
	}

	if B.Verbose {
		fmt.Println("Public Key Path:", setupParams.PublicKeyPath)
		fmt.Println("Master Secret Key Path:", setupParams.MasterSecretKeyPath)
	}
	return setupParams, nil
}

func (B BSW07Demo) KeyGen(keyGenParams VABE.KeyGenParams) (VABE.KeyGenResponse, error) {
	defaults.SetDefaults(&keyGenParams)
	var err error

	publicKey, err := models.LoadPublicKey(keyGenParams.PublicKeyPath)
	if err != nil {
		return VABE.KeyGenResponse{}, fmt.Errorf("Error loading public key: %s", err)
	}

	masterSecretKey, err := models.LoadMasterSecretKey(keyGenParams.MasterSecretKeyPath)
	if err != nil {
		return VABE.KeyGenResponse{}, fmt.Errorf("Error loading master secret key: %s", err)
	}

	attributes, err := models.LoadAttributes(keyGenParams.AttributePath)
	if err != nil {
		return VABE.KeyGenResponse{}, fmt.Errorf("Error loading attributes: %s", err)
	}
	fmt.Printf("Attributes: %v\n", attributes)

	secretKey, proof, err := B.scheme.KeyGen(*masterSecretKey, *publicKey, attributes)

	response := VABE.KeyGenResponse{
		UserPrivateKeyPath:  keyGenParams.UserPrivateKeyPath,
		PrivateKeyProofPath: keyGenParams.PrivateKeyProofPath,
	}
	defaults.SetDefaults(&response)

	err = models.SaveSecretKey(response.UserPrivateKeyPath, secretKey)
	if err != nil {
		return response, fmt.Errorf("Error saving user private key: %s", err)
	}

	err = models.SaveSecretKeyProof(response.PrivateKeyProofPath, proof)
	if err != nil {
		return response, fmt.Errorf("Error saving private key Proof: %s", err)
	}

	if B.Verbose {
		fmt.Println("User Private Key Path:", response.UserPrivateKeyPath)
		fmt.Println("Private Key Proof Path:", response.PrivateKeyProofPath)
	}

	return response, nil
}

func (B BSW07Demo) Encrypt(encryptParams VABE.EncryptParams) (VABE.EncryptResponse, error) {
	defaults.SetDefaults(&encryptParams)

	var err error
	publicKey, err := models.LoadPublicKey(encryptParams.PublicKeyPath)
	if err != nil {
		return VABE.EncryptResponse{}, fmt.Errorf("Error loading public key: %s", err)
	}

	accessPolicy, err := models.LoadAccessPolicy(encryptParams.AccessPolicyPath)
	if err != nil {
		return VABE.EncryptResponse{}, fmt.Errorf("Error loading access policy: %s", err)
	}

	inputData, err := models.LoadPlainFile(encryptParams.InputFilePath)
	//fmt.Println("input file data: \n", string(inputData))

	ciphertext, proof, err := B.scheme.Encrypt(*publicKey, inputData, *accessPolicy)
	if err != nil {
		return VABE.EncryptResponse{}, fmt.Errorf("Encryption Error: %s", err)
	}
	response := VABE.EncryptResponse{
		CipherTextPath:      encryptParams.CipherTextPath,
		CipherTextProofPath: encryptParams.CipherTextProofPath,
	}
	defaults.SetDefaults(&response)

	err = models.SaveCiphertext(response.CipherTextPath, ciphertext)
	if err != nil {
		return response, fmt.Errorf("Error saving Ciphertext: %s", err)
	}

	err = models.SaveCiphertextProof(response.CipherTextProofPath, proof)
	if err != nil {
		return response, fmt.Errorf("Error saving Ciphertext Proof: %s", err)
	}

	if B.Verbose {
		fmt.Println("CipherText Path:", response.CipherTextPath)
		fmt.Println("CipherText Proof Path:", response.CipherTextProofPath)
	}

	return response, nil
}

func (B BSW07Demo) Decrypt(decryptParams VABE.DecryptParams) (VABE.DecryptResponse, error) {
	defaults.SetDefaults(&decryptParams)
	var err error

	publicKey, err := models.LoadPublicKey(decryptParams.PublicKeyPath)
	if err != nil {
		return VABE.DecryptResponse{}, fmt.Errorf("Error loading public key: %s", err)
	}

	userPrivateKey, err := models.LoadSecretKey(decryptParams.UserPrivateKeyPath)
	if err != nil {
		return VABE.DecryptResponse{}, fmt.Errorf("Error loading user private key: %s", err)
	}

	ciphertext, err := models.LoadCiphertext(decryptParams.CipherTextPath)
	if err != nil {
		return VABE.DecryptResponse{}, fmt.Errorf("Error loading Ciphertext: %s", err)
	}

	msg, err := B.scheme.Decrypt(*publicKey, *ciphertext, userPrivateKey)
	if err != nil {
		return VABE.DecryptResponse{}, fmt.Errorf("Decryption Error: %s", err)
	}
	//fmt.Println("msg:", string(msg))

	response := VABE.DecryptResponse{
		DecryptedFilePath: decryptParams.DecryptedFilePath,
	}
	defaults.SetDefaults(&response)

	err = models.SaveDecryptFile(response.DecryptedFilePath, msg)
	if err != nil {
		return response, fmt.Errorf("Error saving decrypted file: %s", err)
	}

	if B.Verbose {
		fmt.Println("Decrypted File Path:", response.DecryptedFilePath)
	}
	return response, nil
}

func (B BSW07Demo) VerifyKey(verifyKeyParams VABE.VerifyKeyParams) bool {
	defaults.SetDefaults(&verifyKeyParams)

	publicKey, err := models.LoadPublicKey(verifyKeyParams.PublicKeyPath)
	if err != nil {
		fmt.Println("Error loading public key:", err)
		return false
	}

	userPrivateKey, err := models.LoadSecretKey(verifyKeyParams.UserPrivateKeyPath)
	if err != nil {
		fmt.Println("Error loading user private key:", err)
		return false
	}

	privateKeyProof, err := models.LoadSecretKeyProof(verifyKeyParams.PrivateKeyProofPath)
	if err != nil {
		fmt.Println("Error loading private key Proof:", err)
		return false
	}

	userAttributes, err := models.LoadAttributes(verifyKeyParams.UserAttributesPath)
	if err != nil {
		fmt.Println("Error loading user attributes:", err)
		return false
	}

	valid, err := B.scheme.VerifyKey(VerifyKeyParams{
		PublicKey:      *publicKey,
		SecretKey:      *userPrivateKey,
		KeyProof:       *privateKeyProof,
		UserAttributes: userAttributes,
	})
	if err != nil {
		fmt.Println("Verification Error:", err)
		return false
	}

	fmt.Println("Verification Result:", valid)
	return valid
}

func (B BSW07Demo) VerifyCiphertext(verifyCiphertextParams VABE.VerifyCiphertextParams) bool {
	defaults.SetDefaults(&verifyCiphertextParams)
	publicKey, err := models.LoadPublicKey(verifyCiphertextParams.PublicKeyPath)
	if err != nil {
		fmt.Printf("Error loading public key: %s", err)
		return false
	}
	ciphertext, err := models.LoadCiphertext(verifyCiphertextParams.CipherTextPath)
	if err != nil {
		fmt.Printf("Error loading Ciphertext: %s", err)
		return false
	}
	proof, err := models.LoadCiphertextProof(verifyCiphertextParams.CipherTextProofPath)
	if err != nil {
		fmt.Printf("Error loading Ciphertext Proof: %s", err)
		return false
	}

	accessPolicy, err := models.LoadAccessPolicy(verifyCiphertextParams.AccessPolicyPath)
	if err != nil {
		fmt.Printf("Error loading access policy: %s", err)
		return false
	}

	valid, err := B.scheme.VerifyCiphertext(VerifyCiphertextParams{
		PublicKey:    *publicKey,
		Ciphertext:   *ciphertext,
		Proof:        *proof,
		AccessPolicy: *accessPolicy,
	})

	if err != nil {
		fmt.Println("Verification Error:", err)
		return false
	}

	return valid
}

func NewBSW07Demo(verbose bool) *BSW07Demo {
	return &BSW07Demo{
		Verbose: verbose,
		scheme: BSW07S{
			Verbose: verbose,
			Salt:    []byte("default_salt"), // Default Salt if none provided
		},
	}
}
