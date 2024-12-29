package aws_kms_eth

import (
	"encoding/asn1"
	"encoding/pem"
	"fmt"
)

// ECPrivateKey represents an ASN.1 encoded EC private key
type ECPrivateKey struct {
	Version    int
	PrivateKey []byte
	Parameters asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey  asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

func ExtractEthereumKeysFromPemPrivateKey(pemData []byte) (string, string, error) {

	// Decode PEM block
	block, _ := pem.Decode(pemData)
	if block == nil {
		return "", "", fmt.Errorf("failed to decode PEM block")
	}

	// Parse the ASN.1 structure directly
	var privKey ECPrivateKey
	if _, err := asn1.Unmarshal(block.Bytes, &privKey); err != nil {
		return "", "", fmt.Errorf("failed to parse ASN.1 structure: %v", err)
	}

	// Convert private key bytes to hex, ensuring it's 64 characters
	privHex := fmt.Sprintf("%064x", privKey.PrivateKey)

	// Extract public key from ASN.1 BitString (removing '04' prefix if present)
	pubKeyBytes := privKey.PublicKey.Bytes
	if len(pubKeyBytes) > 0 && pubKeyBytes[0] == 0x04 {
		pubKeyBytes = pubKeyBytes[1:]
	}
	pubHex := fmt.Sprintf("%x", pubKeyBytes)

	return privHex, pubHex, nil
}
