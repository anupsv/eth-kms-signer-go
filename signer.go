package aws_kms_eth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"math/big"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type KMSClient interface {
	GetPublicKey(ctx context.Context, input *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error)
	Sign(ctx context.Context, input *kms.SignInput) (*kms.SignOutput, error)
}

// ECDSASignature represents the ASN1 structure of ECDSA signature
type asn1EcSig struct {
	R, S *big.Int
}

var (
	secp256k1N     = crypto.S256().Params().N
	secp256k1HalfN = new(big.Int).Div(secp256k1N, big.NewInt(2))
)

// adjustSignatureLength ensures the byte slice is exactly 32 bytes long
func adjustSignatureLength(buffer []byte) []byte {

	if len(buffer) > 32 {
		buffer = buffer[len(buffer)-32:] // Take last 32 bytes
	}

	buffer = bytes.TrimLeft(buffer, "\x00")
	for len(buffer) < 32 {
		zeroBuf := []byte{0}
		buffer = append(zeroBuf, buffer...)
	}
	return buffer
}

// ECDSAPublicKey represents the ASN1 structure of ECDSA public key
type ECDSAPublicKey struct {
	Algorithm struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.ObjectIdentifier
	}
	PublicKey asn1.BitString
}

type KMSEthereumSigner struct {
	kmsClient KMSClient
	keyID     string
}

func NewKMSEthereumSigner(kmsClient KMSClient, keyID string) (*KMSEthereumSigner, error) {

	if kmsClient == nil {
		return nil, errors.New("kms client is nil")
	}

	if keyID == "" {
		return nil, errors.New("keyID is empty")
	}

	return &KMSEthereumSigner{
		kmsClient: kmsClient,
		keyID:     keyID,
	}, nil
}

// SignMessage signs a message using KMS
func (kmsEthereumSigner *KMSEthereumSigner) SignMessage(message []byte) ([]byte, error) {

	if len(message) == 0 {
		return nil, errors.New("message must not be empty")
	}

	// Get the public key first
	pubKey, _, err := kmsEthereumSigner.GetPublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Verify public key is on the curve
	if !secp256k1.S256().IsOnCurve(pubKey.X, pubKey.Y) {
		return nil, errors.New("public key is not on curve")
	}

	// Hash the message according to Ethereum's signing standard
	messageHash := crypto.Keccak256(message)

	// Sign the hash using KMS
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

	// Parse the signature
	publicKeyBytes := crypto.S256().Marshal(pubKey.X, pubKey.Y)

	var sigAsn1 asn1EcSig
	_, err = asn1.Unmarshal(signature.Signature, &sigAsn1)
	if err != nil {
		return nil, fmt.Errorf("asn1.Unmarshal failed: %w", err)
	}

	r := sigAsn1.R.Bytes()
	s := sigAsn1.S.Bytes()

	// Adjust S value according to Ethereum standard
	sBigInt := new(big.Int).SetBytes(s)
	if sBigInt.Cmp(secp256k1HalfN) > 0 {
		s = new(big.Int).Sub(secp256k1N, sBigInt).Bytes()
	}

	// Create RS signature
	rsSignature := append(adjustSignatureLength(r), adjustSignatureLength(s)...)

	// Try with v = 0
	signature0 := append(rsSignature, byte(0))
	recoveredPublicKeyBytes, err := crypto.Ecrecover(messageHash, signature0)
	if err == nil && hex.EncodeToString(recoveredPublicKeyBytes) == hex.EncodeToString(publicKeyBytes) {
		return signature0, nil
	}

	// Try with v = 1
	signature1 := append(rsSignature, byte(1))
	recoveredPublicKeyBytes, err = crypto.Ecrecover(messageHash, signature1)
	if err == nil && hex.EncodeToString(recoveredPublicKeyBytes) == hex.EncodeToString(publicKeyBytes) {
		return signature1, nil
	}

	return nil, errors.New("can not reconstruct public key from signature")
}

// GetPublicKey retrieves the public key from KMS
func (kmsEthereumSigner *KMSEthereumSigner) GetPublicKey() (*ecdsa.PublicKey, *ECDSAPublicKey, error) {
	input := &kms.GetPublicKeyInput{
		KeyId: &kmsEthereumSigner.keyID,
	}

	output, err := kmsEthereumSigner.kmsClient.GetPublicKey(context.Background(), input)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get public key from KMS: %w", err)
	}

	// Decode ASN1 public key
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

	if !pubKeyECDSA.IsOnCurve(pubKeyECDSA.X, pubKeyECDSA.Y) {
		return nil, nil, errors.New("public key is not on curve")
	}

	return pubKeyECDSA, &pubKey, err
}

// GetAddress returns the Ethereum address for this key
func (kmsEthereumSigner *KMSEthereumSigner) GetAddress() (common.Address, error) {

	_, as1PubKey, err := kmsEthereumSigner.GetPublicKey()
	if err != nil {
		return common.Address{}, err
	}

	pubKeyBuffer := as1PubKey.PublicKey.Bytes
	// Ensure the key is in uncompressed format and starts with 0x04
	if len(pubKeyBuffer) == 0 || pubKeyBuffer[0] != 0x04 {
		return common.Address{}, fmt.Errorf("invalid public key format")
	}

	// Remove the prefix (0x04) from the uncompressed key
	pubKeyBuffer = pubKeyBuffer[1:]

	// Hash the public key buffer using Keccak256
	pubKeyHash := crypto.Keccak256(pubKeyBuffer)

	// Take the last 20 bytes as the Ethereum address
	ethAddress := common.BytesToAddress(pubKeyHash[len(pubKeyHash)-20:])
	fmt.Printf("Generated Ethereum address: %s\n", ethAddress.Hex())

	return ethAddress, nil
}
