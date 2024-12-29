package aws_kms_eth

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestExtractEthereumKeys(t *testing.T) {
	tests := []struct {
		name           string
		pemData        string
		wantPrivLength int
		wantPubLength  int
		wantPrivKey    string
		wantPubKey     string
		wantErr        bool
	}{
		{
			name: "Valid secp256k1 key",
			pemData: `-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIJQ5OcT/K3A+426lIjowtmMQQCKx5uTJHWXhN7tD7m3XoAcGBSuBBAAK
oUQDQgAErGj1+7wee1eDEBNeHCoFY+l0jksuRxRPytFkg0fBiW3eGk8m3tKC4REm
XQu4L5x8ndP2887tQQh4FNtMGUTsGA==
-----END EC PRIVATE KEY-----`,
			wantPrivLength: 64,  // 32 bytes in hex
			wantPubLength:  128, // 64 bytes in hex
			wantPrivKey:    "943939c4ff2b703ee36ea5223a30b663104022b1e6e4c91d65e137bb43ee6dd7",
			wantPubKey:     "ac68f5fbbc1e7b578310135e1c2a0563e9748e4b2e47144fcad1648347c1896dde1a4f26ded282e111265d0bb82f9c7c9dd3f6f3ceed41087814db4c1944ec18",
			wantErr:        false,
		},
		{
			name:           "Invalid PEM data",
			pemData:        "invalid pem data",
			wantPrivLength: 0,
			wantPubLength:  0,
			wantErr:        true,
		},
		{
			name: "Empty PEM block",
			pemData: `-----BEGIN EC PRIVATE KEY-----
-----END EC PRIVATE KEY-----`,
			wantPrivLength: 0,
			wantPubLength:  0,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPriv, gotPub, err := ExtractEthereumKeysFromPemPrivateKey([]byte(tt.pemData))

			// Check error expectation
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractEthereumKeys() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return
			}

			// Check private key length
			if len(gotPriv) != tt.wantPrivLength {
				t.Errorf("Private key length = %v, want %v", len(gotPriv), tt.wantPrivLength)
			}

			// Check public key length
			if len(gotPub) != tt.wantPubLength {
				t.Errorf("Public key length = %v, want %v", len(gotPub), tt.wantPubLength)
			}

			// Verify hex format
			if _, err := hex.DecodeString(gotPriv); err != nil {
				t.Errorf("Private key is not valid hex: %v", err)
			}
			if _, err := hex.DecodeString(gotPub); err != nil {
				t.Errorf("Public key is not valid hex: %v", err)
			}

			// Verify no '0x' prefix
			if strings.HasPrefix(gotPriv, "0x") {
				t.Error("Private key should not have 0x prefix")
			}
			if strings.HasPrefix(gotPub, "0x") {
				t.Error("Public key should not have 0x prefix")
			}

			if gotPriv != tt.wantPrivKey {
				t.Errorf("Private key = %v, want %v", gotPriv, tt.wantPrivKey)
			}
			if gotPub != tt.wantPubKey {
				t.Errorf("Public key = %v, want %v", gotPub, tt.wantPubKey)
			}
		})
	}
}

// Test helper function to create a PEM block with invalid ASN.1 data
func TestInvalidASN1(t *testing.T) {
	pemData := `-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIKp9hrXgU1GZvliL8qBOVIzGeHf4jCL9a7LRB3HvO1es
-----END EC PRIVATE KEY-----`

	_, _, err := ExtractEthereumKeysFromPemPrivateKey([]byte(pemData))
	if err == nil {
		t.Error("Expected error for invalid ASN.1 data, got nil")
	}
}
