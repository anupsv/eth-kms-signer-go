package aws_kms_eth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// KMSClient defines the subset of AWS KMS client functionalities required by KMSEthereumSigner.
// It abstracts the AWS KMS client to facilitate easier testing and decoupling.
type KMSClient interface {
	// GetPublicKey retrieves the public key associated with the specified KMS key.
	GetPublicKey(ctx context.Context, input *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error)
	// Sign generates a digital signature for the given message using the specified KMS key.
	Sign(ctx context.Context, input *kms.SignInput) (*kms.SignOutput, error)
}

// asn1EcSig represents the ASN.1 structure of an ECDSA signature.
// It consists of two big integers, R and S, which are components of the signature.
type asn1EcSig struct {
	R, S *big.Int
}

const signatureBufferLength = 32

// adjustSignatureLength ensures that the provided byte slice is exactly 32 bytes long.
// If the slice is longer, it trims the leading bytes. If it's shorter, it pads the slice with leading zeros.
func adjustSignatureLength(buffer []byte) []byte {
	if len(buffer) > signatureBufferLength {
		buffer = buffer[len(buffer)-signatureBufferLength:] // Take last 32 bytes
	}

	buffer = bytes.TrimLeft(buffer, "\x00")
	for len(buffer) < signatureBufferLength {
		zeroBuf := []byte{0}
		buffer = append(zeroBuf, buffer...)
	}
	return buffer
}

// ECDSAPublicKey represents the ASN.1 structure of an ECDSA public key.
// It includes the algorithm identifiers and the public key bit string.
type ECDSAPublicKey struct {
	Algorithm struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.ObjectIdentifier
	}
	PublicKey asn1.BitString
}

// KMSEthereumSigner encapsulates the AWS KMS client and key information required for signing Ethereum messages.
// It handles the interaction with KMS to retrieve public keys and perform signing operations.
type KMSEthereumSigner struct {
	kmsClient      KMSClient // AWS KMS client interface
	keyID          string    // Identifier of the KMS key used for signing
	secp256k1N     *big.Int  // Order N of the secp256k1 curve
	secp256k1HalfN *big.Int  // Half of the order N of the secp256k1 curve
}

// NewKMSEthereumSigner creates a new instance of KMSEthereumSigner.
// It requires a valid KMSClient and the identifier of the KMS key to be used for signing.
//
// Parameters:
//   - kmsClient: An implementation of the KMSClient interface.
//   - keyID: The identifier of the KMS key.
//
// Returns:
//   - A pointer to a KMSEthereumSigner instance.
//   - An error if the kmsClient is nil or the keyID is empty.
func NewKMSEthereumSigner(kmsClient KMSClient, keyID string) (*KMSEthereumSigner, error) {
	if kmsClient == nil {
		return nil, errors.New("kms client is nil")
	}

	if keyID == "" {
		return nil, errors.New("keyID is empty")
	}

	return &KMSEthereumSigner{
		kmsClient:      kmsClient,
		keyID:          keyID,
		secp256k1N:     crypto.S256().Params().N,
		secp256k1HalfN: new(big.Int).Div(crypto.S256().Params().N, big.NewInt(2)),
	}, nil
}

// SignMessage signs the provided message using AWS KMS and returns an Ethereum-compatible signature.
//
// The signing process involves the following steps:
//  1. Retrieve and verify the public key from KMS.
//  2. Hash the message using Ethereum's Keccak256 hashing algorithm.
//  3. Use KMS to sign the hashed message with the specified key.
//  4. Parse the ASN.1 signature returned by KMS.
//  5. Adjust the S component of the signature to conform to Ethereum's standards.
//  6. Reconstruct the signature with the appropriate V value for Ethereum.
//
// Parameters:
//   - message: The byte slice representing the message to be signed.
//
// Returns:
//   - A byte slice containing the Ethereum-compatible signature.
//   - An error if any step in the signing process fails.
func (kmsEthereumSigner *KMSEthereumSigner) SignMessage(message []byte) ([]byte, error) {
	if len(message) == 0 {
		return nil, errors.New("message must not be empty")
	}

	// Step 1: Get the public key
	pubKey, _, err := kmsEthereumSigner.GetPublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Step 2: Verify public key is on the secp256k1 curve
	if !secp256k1.S256().IsOnCurve(pubKey.X, pubKey.Y) {
		return nil, errors.New("public key is not on curve")
	}

	// Step 3: Hash the message according to Ethereum's signing standard
	messageHash := crypto.Keccak256(message)

	// Step 4: Sign the hash using KMS
	signingInput := &kms.SignInput{
		KeyId:            &kmsEthereumSigner.keyID,
		Message:          messageHash,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
		MessageType:      types.MessageTypeDigest,
	}

	signature, err := kmsEthereumSigner.kmsClient.Sign(context.Background(), signingInput)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message with KMS: %w", err)
	}

	// Step 5: Parse the ASN.1 signature
	var sigAsn1 asn1EcSig
	_, err = asn1.Unmarshal(signature.Signature, &sigAsn1)
	if err != nil {
		return nil, fmt.Errorf("asn1.Unmarshal failed: %w", err)
	}

	r := sigAsn1.R.Bytes()
	s := sigAsn1.S.Bytes()

	// Step 6: Adjust S value according to Ethereum standard (low S)
	sBigInt := new(big.Int).SetBytes(s)
	if sBigInt.Cmp(kmsEthereumSigner.secp256k1HalfN) > 0 {
		s = new(big.Int).Sub(kmsEthereumSigner.secp256k1N, sBigInt).Bytes()
	}

	// Step 7: Create RS signature with adjusted R and S
	rsSignature := append(adjustSignatureLength(r), adjustSignatureLength(s)...)

	// Step 8: Attempt to recover the public key with V=0
	signature0 := append(rsSignature, byte(0))
	recoveredPublicKeyBytes, err := crypto.Ecrecover(messageHash, signature0)
	if err == nil && hex.EncodeToString(recoveredPublicKeyBytes) == hex.EncodeToString(crypto.S256().Marshal(pubKey.X, pubKey.Y)) {
		return signature0, nil
	}

	// Step 9: Attempt to recover the public key with V=1
	signature1 := append(rsSignature, byte(1))
	recoveredPublicKeyBytes, err = crypto.Ecrecover(messageHash, signature1)
	if err == nil && hex.EncodeToString(recoveredPublicKeyBytes) == hex.EncodeToString(crypto.S256().Marshal(pubKey.X, pubKey.Y)) {
		return signature1, nil
	}

	return nil, errors.New("cannot reconstruct public key from signature")
}

// GetPublicKey retrieves the public key associated with the KMS key.
// It returns both the ECDSA public key and its ASN.1 structured representation.
//
// The process involves:
//  1. Calling KMS's GetPublicKey API to fetch the public key bytes.
//  2. Decoding the ASN.1 public key structure.
//  3. Unmarshalling the public key into an ECDSA public key.
//
// Returns:
//   - An ECDSA public key instance.
//   - A pointer to the ASN1 structured ECDSAPublicKey.
//   - An error if the retrieval or parsing fails.
func (kmsEthereumSigner *KMSEthereumSigner) GetPublicKey() (*ecdsa.PublicKey, *ECDSAPublicKey, error) {
	input := &kms.GetPublicKeyInput{
		KeyId: &kmsEthereumSigner.keyID,
	}

	output, err := kmsEthereumSigner.kmsClient.GetPublicKey(context.Background(), input)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get public key from KMS: %w", err)
	}

	// Decode ASN.1 public key
	var pubKey ECDSAPublicKey
	_, err = asn1.Unmarshal(output.PublicKey, &pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode public key ASN1: %w", err)
	}

	// Get the public key bytes
	pubKeyECDSA, err := crypto.UnmarshalPubkey(pubKey.PublicKey.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	// Verify that the public key lies on the secp256k1 curve
	if !pubKeyECDSA.IsOnCurve(pubKeyECDSA.X, pubKeyECDSA.Y) {
		return nil, nil, errors.New("public key is not on curve")
	}

	return pubKeyECDSA, &pubKey, nil
}

// GetAddress derives the Ethereum address associated with the KMS-managed public key.
//
// The Ethereum address is obtained by:
//  1. Retrieving the public key from KMS.
//  2. Ensuring the public key is in the uncompressed format.
//  3. Removing the leading byte (0x04) from the uncompressed key.
//  4. Hashing the remaining bytes using Keccak256.
//  5. Taking the last 20 bytes of the hash as the Ethereum address.
//
// Returns:
//   - A common.Address representing the Ethereum address.
//   - An error if the public key retrieval or processing fails.
func (kmsEthereumSigner *KMSEthereumSigner) GetAddress() (common.Address, error) {
	_, asn1PubKey, err := kmsEthereumSigner.GetPublicKey()
	if err != nil {
		return common.Address{}, err
	}

	pubKeyBuffer := asn1PubKey.PublicKey.Bytes
	// Ensure the key is in uncompressed format and starts with 0x04
	if len(pubKeyBuffer) == 0 || pubKeyBuffer[0] != 0x04 {
		return common.Address{}, errors.New("invalid public key format")
	}

	// Remove the prefix (0x04) from the uncompressed key
	pubKeyBuffer = pubKeyBuffer[1:]

	// Hash the public key buffer using Keccak256
	pubKeyHash := crypto.Keccak256(pubKeyBuffer)

	// Take the last 20 bytes as the Ethereum address
	ethAddress := common.BytesToAddress(pubKeyHash[len(pubKeyHash)-20:])

	return ethAddress, nil
}
