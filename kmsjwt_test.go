package kmsjwt

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type mockKMS struct {
	mock.Mock
	kmsiface.KMSAPI
}

func (m *mockKMS) DecryptWithContext(ctx aws.Context, input *kms.DecryptInput, opts ...request.Option) (*kms.DecryptOutput, error) {
	args := m.Called(ctx, input, opts)
	return args.Get(0).(*kms.DecryptOutput), args.Error(1)
}

func (m *mockKMS) EncryptWithContext(ctx aws.Context, input *kms.EncryptInput, opts ...request.Option) (*kms.EncryptOutput, error) {
	args := m.Called(ctx, input, opts)
	return args.Get(0).(*kms.EncryptOutput), args.Error(1)
}

type KMSImplementationTestSuite struct {
	suite.Suite

	ctx     context.Context
	mockAPI *mockKMS
	keyID   string
	sut     jwt.SigningMethod
}

func (s *KMSImplementationTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.mockAPI = new(mockKMS)
	s.keyID = "kms key ID"
	s.sut = New(s.mockAPI, s.keyID)
}

func (s *KMSImplementationTestSuite) TestAlg() {
	s.Equal("KMS", s.sut.Alg())
}

func (s *KMSImplementationTestSuite) TestSignOK() {
	s.mockAPI.On(
		"EncryptWithContext",
		s.ctx,
		mock.MatchedBy(func(input interface{}) bool {
			encryptInput, ok := input.(*kms.EncryptInput)
			if !ok {
				return false
			}
			if *encryptInput.KeyId != s.keyID {
				return false
			}
			if fmt.Sprintf("%x", encryptInput.Plaintext) != "96d62e2abd3e42de5f50330fb8efc4c5599835278077b21e9aa0b33c1df07a1c" {
				return false
			}
			return true
		}),
		[]request.Option(nil),
	).Return(&kms.EncryptOutput{
		CiphertextBlob: []byte("secret"),
		KeyId:          aws.String(s.keyID),
	}, nil)
	ret, err := s.sut.Sign("plaintext", s.ctx)
	s.NoError(err)
	s.Equal("c2VjcmV0", ret)
}

func (s *KMSImplementationTestSuite) TestSignError() {
	s.mockAPI.On(
		"EncryptWithContext",
		s.ctx,
		mock.AnythingOfType("*kms.EncryptInput"),
		[]request.Option(nil),
	).Return((*kms.EncryptOutput)(nil), errors.New("bacon"))
	ret, err := s.sut.Sign("plaintext", s.ctx)
	s.EqualError(err, "key is invalid")
	s.Empty(ret)
}

func (s *KMSImplementationTestSuite) TestSignNotContext() {
	ret, err := s.sut.Sign("plaintext", "bacon")
	s.EqualError(err, "key is not a context")
	s.Empty(ret)
}

func (s *KMSImplementationTestSuite) TestVerifyOKWithCache() {
	plaintext, err := base64.StdEncoding.DecodeString("ve/CWUJr0IbREmEIrDlVpsFRZMofWR4Icux8SeRALmo=")
	s.NoError(err)
	s.mockAPI.On(
		"DecryptWithContext",
		s.ctx,
		mock.MatchedBy(func(input interface{}) bool {
			decryptInput, ok := input.(*kms.DecryptInput)
			if !ok {
				return false
			}
			if string(decryptInput.CiphertextBlob) != "bacon\n" {
				return false
			}
			return true
		}),
		[]request.Option(nil),
	).Once().Return(&kms.DecryptOutput{
		KeyId:     aws.String(s.keyID),
		Plaintext: plaintext,
	}, nil)
	s.NoError(s.sut.Verify("signing", "YmFjb24K", s.ctx))

	// Ensure cache is warmed.
	value, ok := s.sut.(*kmsClient).cache.Get("signing")
	s.True(ok)
	s.Equal("YmFjb24K", value.(string))
	s.NoError(s.sut.Verify("signing", "YmFjb24K", s.ctx))
}

func (s *KMSImplementationTestSuite) TestVerifyOKWithoutCache() {
	s.sut = New(s.mockAPI, s.keyID, DisableCache)
	plaintext, err := base64.StdEncoding.DecodeString("ve/CWUJr0IbREmEIrDlVpsFRZMofWR4Icux8SeRALmo=")
	s.NoError(err)
	s.mockAPI.On(
		"DecryptWithContext",
		s.ctx,
		mock.MatchedBy(func(input interface{}) bool {
			decryptInput, ok := input.(*kms.DecryptInput)
			if !ok {
				return false
			}
			if string(decryptInput.CiphertextBlob) != "bacon\n" {
				return false
			}
			return true
		}),
		[]request.Option(nil),
	).Twice().Return(&kms.DecryptOutput{
		KeyId:     aws.String(s.keyID),
		Plaintext: plaintext,
	}, nil)
	s.NoError(s.sut.Verify("signing", "YmFjb24K", s.ctx))
	s.Nil(s.sut.(*kmsClient).cache)
	s.NoError(s.sut.Verify("signing", "YmFjb24K", s.ctx))
}

func (s *KMSImplementationTestSuite) TestVerifyDecryptFails() {
	s.mockAPI.On(
		"DecryptWithContext",
		s.ctx,
		mock.AnythingOfType("*kms.DecryptInput"),
		[]request.Option(nil),
	).Return((*kms.DecryptOutput)(nil), errors.New("bacon"))
	s.EqualError(s.sut.Verify("signing", "YmFjb24K", s.ctx), "kms: verification error")
}

func (s *KMSImplementationTestSuite) TestVerifyDifferentKey() {
	s.mockAPI.On(
		"DecryptWithContext",
		s.ctx,
		mock.AnythingOfType("*kms.DecryptInput"),
		[]request.Option(nil),
	).Return(&kms.DecryptOutput{KeyId: aws.String("huh?")}, nil)
	s.EqualError(s.sut.Verify("signing", "YmFjb24K", s.ctx), "key is invalid")
}

func (s *KMSImplementationTestSuite) TestVerifyDoesNotCompare() {
	s.mockAPI.On(
		"DecryptWithContext",
		s.ctx,
		mock.AnythingOfType("*kms.DecryptInput"),
		[]request.Option(nil),
	).Return(&kms.DecryptOutput{KeyId: aws.String(s.keyID), Plaintext: []byte("wrong")}, nil)
	s.EqualError(s.sut.Verify("signing", "YmFjb24K", s.ctx), "kms: verification error")
}

func (s *KMSImplementationTestSuite) TestVerifyNotContext() {
	s.EqualError(s.sut.Verify("signing", "signature", "not context"), "key is not a context")
}

func TestKMSImplementation(t *testing.T) {
	suite.Run(t, new(KMSImplementationTestSuite))
}
