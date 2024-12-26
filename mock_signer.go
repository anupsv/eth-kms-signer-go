package aws_kms_eth

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type MockKMSClient struct {
	MockGetPublicKey func(ctx context.Context, input *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error)
	MockSign         func(ctx context.Context, input *kms.SignInput) (*kms.SignOutput, error)
}

func (m *MockKMSClient) GetPublicKey(ctx context.Context, input *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
	if m.MockGetPublicKey != nil {
		return m.MockGetPublicKey(ctx, input)
	}
	return nil, nil
}

func (m *MockKMSClient) Sign(ctx context.Context, input *kms.SignInput) (*kms.SignOutput, error) {
	if m.MockSign != nil {
		return m.MockSign(ctx, input)
	}
	return nil, nil
}
