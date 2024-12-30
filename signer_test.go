package aws_kms_eth

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/ory/dockertest/v3"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	_secp256k1N     = crypto.S256().Params().N
	_secp256k1HalfN = new(big.Int).Div(_secp256k1N, big.NewInt(2))
)

// LocalstackKMSClient implements KMSClient interface using actual KMS calls to Localstack.
type LocalstackKMSClient struct {
	client *kms.Client
}

func (l *LocalstackKMSClient) GetPublicKey(
	ctx context.Context,
	input *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
	return l.client.GetPublicKey(ctx, input)
}

func (l *LocalstackKMSClient) Sign(
	ctx context.Context,
	input *kms.SignInput) (*kms.SignOutput, error) {
	return l.client.Sign(ctx, input)
}

type testContext struct {
	kmsClient KMSClient
	keyID     string
	resource  *dockertest.Resource
}

type fuzzContext struct {
	kmsClient KMSClient
	keyID     string
	pool      *dockertest.Pool
	resource  *dockertest.Resource
	signer    *KMSEthereumSigner
	address   common.Address
}

var (
	setupOnce sync.Once
	fuzzCtx   *fuzzContext
	setupErr  error
)

func setupFuzzTest() (*fuzzContext, error) {
	setupOnce.Do(func() {
		customResolver := aws.EndpointResolverWithOptionsFunc(
			func(_, _ string, _ ...interface{}) (aws.Endpoint, error) {
				return aws.Endpoint{
					URL:           "http://localhost:4566",
					SigningRegion: "us-east-1",
				}, nil
			})

		cfg, err := config.LoadDefaultConfig(context.Background(),
			config.WithRegion("us-east-1"),
			config.WithEndpointResolverWithOptions(customResolver),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "test")),
		)
		if err != nil {
			setupErr = fmt.Errorf("failed to load AWS config: %w", err)
			return
		}

		kmsClient := kms.NewFromConfig(cfg)
		localstackClient := &LocalstackKMSClient{client: kmsClient}

		// Wait for localstack and create key
		var keyID string
		resp, err := kmsClient.CreateKey(context.Background(), &kms.CreateKeyInput{
			KeySpec:  types.KeySpecEccSecgP256k1,
			KeyUsage: types.KeyUsageTypeSignVerify,
		})
		if err != nil {
			setupErr = fmt.Errorf("failed to create KMS key: %w", err)
			return
		}

		keyID = *resp.KeyMetadata.KeyId

		signer, err := NewKMSEthereumSigner(localstackClient, keyID)
		if err != nil {
			setupErr = fmt.Errorf("failed to create signer: %w", err)
			return
		}
		address, err := signer.GetAddress()
		if err != nil {
			setupErr = fmt.Errorf("failed to get address: %w", err)
			return
		}

		fuzzCtx = &fuzzContext{
			kmsClient: localstackClient,
			keyID:     keyID,
			signer:    signer,
			address:   address,
		}
	})

	return fuzzCtx, setupErr
}

func setupLocalstack(t *testing.T) *testContext {
	customResolver := aws.EndpointResolverWithOptionsFunc(
		func(_, _ string, _ ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				URL:           "http://localhost:4566",
				SigningRegion: "us-east-1",
			}, nil
		})

	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion("us-east-1"),
		config.WithEndpointResolverWithOptions(customResolver),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "test")),
	)
	require.NoError(t, err)

	kmsClient := kms.NewFromConfig(cfg)
	localstackClient := &LocalstackKMSClient{client: kmsClient}

	// Wait for localstack
	var keyID string
	resp, err := kmsClient.CreateKey(context.Background(), &kms.CreateKeyInput{
		KeySpec:  types.KeySpecEccSecgP256k1,
		KeyUsage: types.KeyUsageTypeSignVerify,
	})
	if err != nil {
		panic(err)
	}
	keyID = *resp.KeyMetadata.KeyId

	return &testContext{
		kmsClient: localstackClient,
		keyID:     keyID,
	}
}

func TestSignMessage(t *testing.T) {
	mockClient := &MockKMSClient{
		MockGetPublicKey: func(_ context.Context, _ *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
			return &kms.GetPublicKeyOutput{
				PublicKey: []byte{0x04, 0x01, 0x02, 0x03}, // Mock public key bytes
			}, nil
		},
		MockSign: func(_ context.Context, _ *kms.SignInput) (*kms.SignOutput, error) {
			return &kms.SignOutput{
				Signature: []byte{0x30, 0x44, 0x02, 0x20}, // Mock signature bytes
			}, nil
		},
	}

	signer, err := NewKMSEthereumSigner(mockClient, "test-key-id")
	if err != nil {
		t.Fatalf("Expected error, got nil")
	}
	message := []byte("test message")

	_, err = signer.SignMessage(message)
	if err == nil {
		t.Fatalf("expected error, got none!!")
	}
}

func TestNewKMSEthereumSigner(t *testing.T) {
	mockClient := &MockKMSClient{}
	keyID := "test-key-id"

	signer, err := NewKMSEthereumSigner(mockClient, keyID)
	if err != nil {
		t.Fatalf("Expected error, got nil")
	}

	if signer.kmsClient != mockClient {
		t.Errorf("Expected kmsClient to be %v, got %v", mockClient, signer.kmsClient)
	}
	if signer.keyID != keyID {
		t.Errorf("Expected keyID to be %v, got %v", keyID, signer.keyID)
	}
}

func TestGetPublicKey_InvalidKey(t *testing.T) {
	mockClient := &MockKMSClient{
		MockGetPublicKey: func(_ context.Context, _ *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
			return &kms.GetPublicKeyOutput{
				PublicKey: []byte{0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
			}, nil
		},
	}

	signer, err := NewKMSEthereumSigner(mockClient, "test-key-id")
	if err != nil {
		t.Fatalf("Expected error, got nil")
	}
	_, _, err = signer.GetPublicKey()
	if err == nil {
		t.Fatalf("expected error, got none!")
	}
}

func TestGetPublicKey_KMSError(t *testing.T) {
	mockClient := &MockKMSClient{
		MockGetPublicKey: func(_ context.Context, _ *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
			return nil, fmt.Errorf("mock KMS error")
		},
	}

	signer, err := NewKMSEthereumSigner(mockClient, "test-key-id")
	if err != nil {
		t.Fatalf("Expected error, got nil")
	}
	_, _, err = signer.GetPublicKey()
	if err == nil {
		t.Fatalf("Expected error, got nil")
	}
}

func TestGetAddress_InvalidKey(t *testing.T) {
	mockClient := &MockKMSClient{
		MockGetPublicKey: func(_ context.Context, input *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
			return &kms.GetPublicKeyOutput{
				PublicKey: append([]byte{0x04}, bytes.Repeat([]byte{0x01}, 64)...),
			}, nil
		},
	}

	signer, err := NewKMSEthereumSigner(mockClient, "test-key-id")
	if err != nil {
		t.Fatalf("Expected error, got nil")
	}

	_, err = signer.GetAddress()
	if err == nil {
		t.Fatalf("Expected error, got nil")
	}
}

func TestSignMessage_InvalidKey(t *testing.T) {
	mockClient := &MockKMSClient{
		MockGetPublicKey: func(_ context.Context, input *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
			return &kms.GetPublicKeyOutput{
				PublicKey: append([]byte{0x04}, bytes.Repeat([]byte{0x01}, 64)...),
			}, nil
		},
		MockSign: func(_ context.Context, input *kms.SignInput) (*kms.SignOutput, error) {
			return &kms.SignOutput{
				Signature: []byte{0x30, 0x44, 0x02, 0x20}, // Mocked signature
			}, nil
		},
	}

	signer, err := NewKMSEthereumSigner(mockClient, "test-key-id")
	if err != nil {
		t.Fatalf("Expected error, got nil")
	}
	message := []byte("test message")

	_, err = signer.SignMessage(message)
	if err == nil {
		t.Fatalf("Expected error, got nil")
	}
}

func TestSignMessage_InvalidMessage(t *testing.T) {
	mockClient := &MockKMSClient{
		MockSign: func(_ context.Context, input *kms.SignInput) (*kms.SignOutput, error) {
			return nil, fmt.Errorf("mock KMS error")
		},
	}

	signer, err := NewKMSEthereumSigner(mockClient, "test-key-id")
	if err != nil {
		t.Fatalf("Expected error, got nil")
	}

	var message []byte

	_, err = signer.SignMessage(message)
	if err == nil {
		t.Fatalf("Expected error, got nil")
	}
}

func TestSigner_EmptyKeyID(t *testing.T) {
	mockClient := &MockKMSClient{}
	_, err := NewKMSEthereumSigner(mockClient, "")

	if err == nil {
		t.Fatalf("Expected error for empty key ID, got nil")
	}
}

func TestGetPublicKey_InvalidASN1(t *testing.T) {
	mockClient := &MockKMSClient{
		MockGetPublicKey: func(_ context.Context, input *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
			return &kms.GetPublicKeyOutput{
				PublicKey: []byte{0x00, 0x01}, // Invalid ASN.1 data
			}, nil
		},
	}

	signer, err := NewKMSEthereumSigner(mockClient, "test-key-id")
	if err != nil {
		t.Fatalf("Expected error for empty key ID, got nil")
	}

	_, _, err = signer.GetPublicKey()
	if err == nil {
		t.Fatalf("Expected error, got nil")
	}
}

func TestKMSEthereumSigner(t *testing.T) {
	ctx := setupLocalstack(t)
	signer, err := NewKMSEthereumSigner(ctx.kmsClient, ctx.keyID)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	t.Run("Get public key and address", func(t *testing.T) {
		pubKey, _, err := signer.GetPublicKey()
		require.NoError(t, err)
		require.NotNil(t, pubKey)

		address, err := signer.GetAddress()
		require.NoError(t, err)
		assert.True(t, common.IsHexAddress(address.Hex()))
	})

	t.Run("Sign and recover address", func(t *testing.T) {
		message := []byte("Hello, Ethereum!")
		messageHash := crypto.Keccak256(message)

		// Get expected address
		expectedAddr, err := signer.GetAddress()
		require.NoError(t, err)

		// Sign message
		signature, err := signer.SignMessage(message)
		require.NoError(t, err)
		assert.Len(t, signature, 65)

		// Extract R, S, V
		// r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:64])
		v := signature[64]
		assert.True(t, v == 0 || v == 1)

		// Verify S is in lower half per EIP-2

		assert.LessOrEqual(t, s.Cmp(_secp256k1HalfN), 0)

		// Recover address
		pubKeyBytes, err := crypto.Ecrecover(messageHash, signature)
		require.NoError(t, err)

		pubKey, err := crypto.UnmarshalPubkey(pubKeyBytes)
		require.NoError(t, err)

		recoveredAddr := crypto.PubkeyToAddress(*pubKey)
		assert.Equal(t, expectedAddr, recoveredAddr)
	})

	t.Run("Multiple signatures", func(t *testing.T) {
		expectedAddr, err := signer.GetAddress()
		require.NoError(t, err)

		messages := []string{
			"Message 1",
			"Message 2",
			"Message 3",
		}

		for _, msg := range messages {
			signature, err := signer.SignMessage([]byte(msg))
			require.NoError(t, err)

			messageHash := crypto.Keccak256([]byte(msg))
			pubKeyBytes, err := crypto.Ecrecover(messageHash, signature)
			require.NoError(t, err)

			pubKey, err := crypto.UnmarshalPubkey(pubKeyBytes)
			require.NoError(t, err)

			recoveredAddr := crypto.PubkeyToAddress(*pubKey)
			assert.Equal(t, expectedAddr, recoveredAddr)
		}
	})
}

func FuzzSignMessage(f *testing.F) {
	ctx, err := setupFuzzTest()
	if err != nil {
		f.Fatal(err)
	}

	// Add seed corpus
	f.Add([]byte("Hello, World!"))
	f.Add([]byte{})
	f.Add([]byte{0xFF, 0x00, 0xFF})
	f.Add([]byte("A longer message that might cause issues with ASN.1 encoding"))
	f.Add(make([]byte, 1024)) // 1KB of zeros

	f.Fuzz(func(t *testing.T, message []byte) {
		signature, err := ctx.signer.SignMessage(message)
		if err != nil {
			t.Logf("Failed to sign message: %v", err)
			return
		}

		// Basic signature validation
		if len(signature) != 65 {
			t.Errorf("Invalid signature length: got %d, want 65", len(signature))
			return
		}

		// Verify v value
		v := signature[64]
		if v != 0 && v != 1 {
			t.Errorf("Invalid v value: %d", v)
			return
		}

		// Verify s is in lower half per EIP-2
		s := new(big.Int).SetBytes(signature[32:64])
		if s.Cmp(_secp256k1HalfN) > 0 {
			t.Error("S value is not in lower half of curve order")
			return
		}

		// Verify signature by recovering address
		messageHash := crypto.Keccak256(message)
		recoveredPub, err := crypto.Ecrecover(messageHash, signature)
		if err != nil {
			t.Errorf("Failed to recover public key: %v", err)
			return
		}

		recoveredAddr := common.BytesToAddress(crypto.Keccak256(recoveredPub[1:])[12:])
		if recoveredAddr != ctx.address {
			t.Errorf("Address mismatch: got %s, want %s", recoveredAddr.Hex(), ctx.address.Hex())
		}
	})
}

func FuzzConcurrentSigning(f *testing.F) {
	ctx, err := setupFuzzTest()
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte("Base message"), uint8(2))

	f.Fuzz(func(t *testing.T, baseMessage []byte, numGoroutines uint8) {
		if len(baseMessage) == 0 || numGoroutines == 0 {
			return
		}

		// Limit number of goroutines to reasonable value
		numWorkers := int(numGoroutines%20) + 1
		var wg sync.WaitGroup
		errCh := make(chan error, numWorkers)

		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()

				// Create unique message for each goroutine
				message := append(baseMessage, byte(index))
				signature, err := ctx.signer.SignMessage(message)
				if err != nil {
					errCh <- fmt.Errorf("worker %d signing failed: %v", index, err)
					return
				}

				messageHash := crypto.Keccak256(message)
				recoveredPub, err := crypto.Ecrecover(messageHash, signature)
				if err != nil {
					errCh <- fmt.Errorf("worker %d recovery failed: %v", index, err)
					return
				}

				recoveredAddr := common.BytesToAddress(crypto.Keccak256(recoveredPub[1:])[12:])
				if recoveredAddr != ctx.address {
					errCh <- fmt.Errorf("worker %d address mismatch", index)
					return
				}
			}(i)
		}

		wg.Wait()
		close(errCh)

		for err := range errCh {
			t.Error(err)
		}
	})
}

func FuzzPublicKeyFormat(f *testing.F) {
	// Add seed corpus
	f.Add([]byte("Hello, World!"))
	f.Add([]byte{})
	f.Add([]byte{0xFF, 0x00, 0xFF})
	f.Add([]byte("A longer message that might cause issues with ASN.1 encoding"))
	f.Add(make([]byte, 1024))

	f.Fuzz(func(t *testing.T, pubKeyInput []byte) {
		mockClient := &MockKMSClient{
			MockGetPublicKey: func(ctx context.Context, input *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
				return &kms.GetPublicKeyOutput{
					PublicKey: pubKeyInput, // Mock public key bytes
				}, nil
			},
			MockSign: func(ctx context.Context, input *kms.SignInput) (*kms.SignOutput, error) {
				return &kms.SignOutput{
					Signature: []byte{}, // Mock signature, for signature matching.
				}, nil
			},
		}

		signer, err := NewKMSEthereumSigner(mockClient, "test-key-id")
		if err != nil {
			t.Fatalf("Expected error, got nil")
		}

		_, _, err = signer.GetPublicKey()
		if err == nil {
			t.Errorf("Expected Error, got valid pubkey: %v", pubKeyInput)
			return
		}
	})
}

type AWSResponse struct {
	Key   string `json:"Key"`
	Token string `json:"Token"`
}

//func TestKeyImportProcess(t *testing.T) {
//	// Create temporary directory for our test files
//	tmpDir, err := os.MkdirTemp("", "key-import-test")
//	if err != nil {
//		t.Fatalf("Failed to create temp directory: %v", err)
//	}
//	defer os.RemoveAll(tmpDir)
//
//	customResolver := aws.EndpointResolverWithOptionsFunc(
//		func(_, _ string, _ ...interface{}) (aws.Endpoint, error) {
//			return aws.Endpoint{
//				URL:           "http://localhost:4566",
//				SigningRegion: "us-east-1",
//			}, nil
//		})
//
//	cfg, err := config.LoadDefaultConfig(context.Background(),
//		config.WithRegion("us-east-1"),
//		config.WithEndpointResolverWithOptions(customResolver),
//		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "test")),
//	)
//	require.NoError(t, err)
//
//	kmsClient := kms.NewFromConfig(cfg)
//
//	// Wait for localstack
//	var keyIDSignVerify string
//	resp, err := kmsClient.CreateKey(context.Background(), &kms.CreateKeyInput{
//		KeySpec:  types.KeySpecEccSecgP256k1,
//		KeyUsage: types.KeyUsageTypeSignVerify,
//		Origin:   types.OriginTypeExternal,
//	})
//	if err != nil {
//		panic(err)
//	}
//
//	keyIDSignVerify = *resp.KeyMetadata.KeyId
//
//	localstackClient := &LocalstackKMSClient{client: kmsClient}
//
//	signer, err := NewKMSEthereumSigner(localstackClient, keyIDSignVerify)
//
//	if err != nil {
//		t.Fatalf("Expected no error, got %v", err)
//	}
//
//	t.Run("Complete Key Import Process", func(t *testing.T) {
//		// Step 1: Generate secp256k1 private key
//		privKeyPath := filepath.Join(tmpDir, "ecc-secp256k1-private-key.pem")
//		cmd := exec.Command("openssl", "ecparam",
//			"-name", "secp256k1",
//			"-genkey",
//			"-noout",
//			"-out", privKeyPath)
//
//		if output, err := cmd.CombinedOutput(); err != nil {
//			t.Fatalf("Failed to generate private key: %v\nOutput: %s", err, output)
//		}
//
//		// Step 2: Get AWS KMS parameters for import
//		cmd = exec.Command("aws", "kms", "get-parameters-for-import",
//			"--region", "us-east-1",
//			"--endpoint", "http://localhost:4566",
//			"--key-id", keyIDSignVerify,
//			"--wrapping-algorithm", "RSAES_OAEP_SHA_256",
//			"--wrapping-key-spec", "RSA_2048",
//			"--query", "{Key:PublicKey,Token:ImportToken}",
//			"--output", "json")
//
//		output, err := cmd.Output()
//		if err != nil {
//			t.Fatalf("Failed to get AWS parameters: %v", err)
//		}
//
//		var awsResp AWSResponse
//		if err := json.Unmarshal(output, &awsResp); err != nil {
//			t.Fatalf("Failed to parse AWS response: %v", err)
//		}
//
//		// Write public key and import token to files
//		pubKeyPath := filepath.Join(tmpDir, "PublicKey.bin")
//		tokenPath := filepath.Join(tmpDir, "ImportToken.bin")
//
//		pubKeyData, err := base64.StdEncoding.DecodeString(awsResp.Key)
//		if err != nil {
//			t.Fatalf("Failed to decode public key: %v", err)
//		}
//		if err := os.WriteFile(pubKeyPath, pubKeyData, 0600); err != nil {
//			t.Fatalf("Failed to write public key: %v", err)
//		}
//
//		tokenData, err := base64.StdEncoding.DecodeString(awsResp.Token)
//		if err != nil {
//			t.Fatalf("Failed to decode import token: %v", err)
//		}
//		if err := os.WriteFile(tokenPath, tokenData, 0600); err != nil {
//			t.Fatalf("Failed to write import token: %v", err)
//		}
//
//		// Step 3: Convert to PKCS8 DER format
//		derPath := filepath.Join(tmpDir, "ec-secp256k1-priv-key.der")
//		cmd = exec.Command("openssl", "pkcs8",
//			"-topk8",
//			"-outform", "der",
//			"-nocrypt",
//			"-in", privKeyPath,
//			"-out", derPath)
//
//		if output, err := cmd.CombinedOutput(); err != nil {
//			t.Fatalf("Failed to convert to PKCS8 DER: %v\nOutput: %s", err, output)
//		}
//
//		// Step 4: Encrypt the key material
//		encryptedPath := filepath.Join(tmpDir, "EncryptedKeyMaterial.bin")
//		cmd = exec.Command("openssl", "pkeyutl",
//			"-encrypt",
//			"-in", derPath,
//			"-out", encryptedPath,
//			"-inkey", pubKeyPath,
//			"-keyform", "DER",
//			"-pubin",
//			"-pkeyopt", "rsa_padding_mode:oaep",
//			"-pkeyopt", "rsa_oaep_md:sha256")
//
//		if output, err := cmd.CombinedOutput(); err != nil {
//			t.Fatalf("Failed to encrypt key material: %v\nOutput: %s", err, output)
//		}
//
//		// Step 5: Import the key material to AWS KMS
//		cmd = exec.Command("aws", "kms", "import-key-material",
//			"--endpoint", "http://localhost:4566",
//			"--region", "us-east-1",
//			"--key-id", keyIDSignVerify,
//			"--encrypted-key-material", fmt.Sprintf("fileb://%s", encryptedPath),
//			"--import-token", fmt.Sprintf("fileb://%s", tokenPath),
//			"--expiration-model", "KEY_MATERIAL_DOES_NOT_EXPIRE")
//
//		if output, err := cmd.CombinedOutput(); err != nil {
//			t.Fatalf("Failed to import key material: %v\nOutput: %s", err, output)
//		}
//
//		// Optional: Verify the imported key is active
//		cmd = exec.Command("aws", "kms", "describe-key",
//			"--endpoint", "http://localhost:4566",
//			"--region", "us-east-1",
//			"--key-id", keyIDSignVerify,
//			"--query", "KeyMetadata.KeyState",
//			"--output", "text")
//
//		output, err = cmd.Output()
//		if err != nil {
//			t.Fatalf("Failed to verify key state: %v", err)
//		}
//
//		keyState := strings.TrimSpace(string(output))
//		if keyState != "Enabled" {
//			t.Errorf("Unexpected key state: got %s, want Enabled", keyState)
//		}
//
//		pubKey, _, err := signer.GetPublicKey()
//		require.NoError(t, err)
//		require.NotNil(t, pubKey)
//
//		address, err := signer.GetAddress()
//		require.NoError(t, err)
//		assert.True(t, common.IsHexAddress(address.Hex()))
//
//		message := []byte("Hello, Ethereum!")
//		messageHash := crypto.Keccak256(message)
//
//		// Get expected address
//		expectedAddr, err := signer.GetAddress()
//		require.NoError(t, err)
//
//		// Sign message
//		signature, err := signer.SignMessage(message)
//		require.NoError(t, err)
//		assert.Len(t, signature, 65)
//
//		// Extract R, S, V
//		// r := new(big.Int).SetBytes(signature[:32])
//		s := new(big.Int).SetBytes(signature[32:64])
//		v := signature[64]
//		assert.True(t, v == 0 || v == 1)
//
//		// Verify S is in lower half per EIP-2
//
//		assert.LessOrEqual(t, s.Cmp(_secp256k1HalfN), 0)
//
//		// Recover address
//		pubKeyBytes, err := crypto.Ecrecover(messageHash, signature)
//		require.NoError(t, err)
//
//		pubKey2, err := crypto.UnmarshalPubkey(pubKeyBytes)
//		require.NoError(t, err)
//
//		recoveredAddr := crypto.PubkeyToAddress(*pubKey2)
//		assert.Equal(t, expectedAddr, recoveredAddr)
//	})
//}
