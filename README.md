# AWS KMS Ethereum Signer

AWS KMS Ethereum Signer is a Go package that converts **AWS Key Management Service (KMS)** keys to **Ethereum** compatible public address and signatures.
## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
    - [Initialization](#initialization)
    - [Signing Messages](#signing-messages)
    - [Retrieving Ethereum Address](#retrieving-ethereum-address)
- [API Reference](#api-reference)
    - [Types](#types)
    - [Functions](#functions)
    - [Interfaces](#interfaces)
- [Contributing](#contributing)

## Features

- **Secure ECDSA Signing**: Utilize AWS KMS-managed secp256k1 keys to sign messages securely.
- **Ethereum Compatibility**: Convert AWS KMS signatures (DER-encoded) into Ethereum's 65-byte format, including the recovery identifier (`V`).
- **Public Key Retrieval**: Fetch and validate public keys from AWS KMS, ensuring they lie on the secp256k1 curve.
- **Ethereum Address Generation**: Derive Ethereum addresses from KMS-managed public keys using Keccak256 hashing.

## Installation

To install the `aws-kms-eth` package, use the following `go get` command:

```bash
go get github.com/anupsv/aws-kms-eth
```

## Usage

### Initialization

To use the KMSEthereumSigner, first initialize it by providing a KMS client and the KMS key ID.

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/kms"
    "github.com/anupsv/aws-kms-eth"
)

func main() {
    // Load the AWS configuration
    cfg, err := config.LoadDefaultConfig(context.TODO())
    if err != nil {
        log.Fatalf("unable to load SDK config, %v", err)
    }

    // Create a KMS client
    kmsClient := kms.NewFromConfig(cfg)

    // Specify your KMS key ID
    keyID := "your-kms-key-id"

    // Initialize the KMSEthereumSigner
    signer, err := aws_kms_eth.NewKMSEthereumSigner(kmsClient, keyID)
    if err != nil {
        log.Fatalf("Failed to create KMSEthereumSigner: %v", err)
    }

    fmt.Println("KMSEthereumSigner initialized successfully")
}
```

### Signing Messages

To sign a message using AWS KMS and obtain an Ethereum-compatible signature:

```go
package main

import (
    "fmt"
    "log"

    "github.com/anupsv/aws-kms-eth"
)

func main() {
    // Initialize signer as shown in Initialization section

    message := []byte("Hello, Ethereum!")

    signature, err := signer.SignMessage(message)
    if err != nil {
        log.Fatalf("Failed to sign message: %v", err)
    }

    fmt.Printf("Signature: %x\n", signature)
}
```


### Retrieving Ethereum Address

To retrieve the Ethereum address associated with the KMS-managed key:

```go
package main

import (
    "fmt"
    "log"
	
    "github.com/anupsv/aws-kms-eth"
)

func main() {
    // Initialize signer as shown in Initialization section

    ethAddress, err := signer.GetAddress()
    if err != nil {
        log.Fatalf("Failed to get Ethereum address: %v", err)
    }

    fmt.Printf("Ethereum Address: %s\n", ethAddress.Hex())
}
```


## API Reference

### Types

```go
KMSEthereumSigner
```

A signer that uses AWS KMS to sign messages and interact with Ethereum-compatible signatures.

```go
type KMSEthereumSigner struct {
    kmsClient      KMSClient
    keyID          string
    secp256k1N     *big.Int
    secp256k1HalfN *big.Int
}
```

### Functions

```go
NewKMSEthereumSigner
```

Creates a new instance of KMSEthereumSigner.

```go
func NewKMSEthereumSigner(kmsClient KMSClient, keyID string) (*KMSEthereumSigner, error)
```

Parameters:
- `kmsClient`: An implementation of the KMSClient interface.
- `ID`: The identifier of the AWS KMS key to use.

Returns:
- `*KMSEthereumSigner`: A new instance of the signer.
- `error`: An error if initialization fails.

```go
SignMessage
```

Signs a message using the AWS KMS key and returns an Ethereum-compatible signature.

```go
func (kmsEthereumSigner *KMSEthereumSigner) SignMessage(message []byte) ([]byte, error)
```

Parameters:
- `message`: The message to sign.

Returns:
- `[]byte`: The 65-byte Ethereum-compatible signature.
- `error`: An error if signing fails.

```go
GetPublicKey
```

Retrieves the public key from AWS KMS.

```go
func (kmsEthereumSigner *KMSEthereumSigner) GetPublicKey() (*ecdsa.PublicKey, *ECDSAPublicKey, error)
```

Returns:
- `*ecdsa.PublicKey`: The parsed ECDSA public key.
- `*ECDSAPublicKey`: The ASN.1 structure of the public key.
- `error`: An error if retrieval or parsing fails.

```go
GetAddress
```

Derives the Ethereum address from the KMS-managed public key.

```go
func (kmsEthereumSigner *KMSEthereumSigner) GetAddress() (common.Address, error)
```

Returns:
- `common.Address`: The Ethereum address.
- `error`: An error if address derivation fails.

### Interfaces

```go
KMSClient
```

An interface that abstracts AWS KMS client methods used by KMSEthereumSigner.

```go
type KMSClient interface {
    GetPublicKey(ctx context.Context, input *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error)
    Sign(ctx context.Context, input *kms.SignInput) (*kms.SignOutput, error)
}
```

Purpose: Allows for dependency injection, enabling easy mocking during testing.

## Contributing

Please ensure that your code adheres to the existing coding standards and that all tests pass.

