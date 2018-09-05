package kmsjwt

import (
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
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

func (m *mockKMS) Decrypt(input *kms.DecryptInput) (*kms.DecryptOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*kms.DecryptOutput), args.Error(1)
}

func (m *mockKMS) Encrypt(input *kms.EncryptInput) (*kms.EncryptOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*kms.EncryptOutput), args.Error(1)
}

type KMSImplementationTestSuite struct {
	suite.Suite
	mockAPI *mockKMS
	keyID   string
	sut     jwt.SigningMethod
}

func (s *KMSImplementationTestSuite) SetupTest() {
	s.mockAPI = new(mockKMS)
	s.keyID = "kms key ID"
	s.sut = New(s.mockAPI, s.keyID)
}

func (s *KMSImplementationTestSuite) TestAlg() {
	s.Equal("KMS", s.sut.Alg())
}

func (s *KMSImplementationTestSuite) TestSignOK() {
	s.mockAPI.On("Encrypt", mock.MatchedBy(func(input interface{}) bool {
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
	})).Return(&kms.EncryptOutput{
		CiphertextBlob: []byte("secret"),
		KeyId:          aws.String(s.keyID),
	}, nil)
	ret, err := s.sut.Sign("plaintext", nil)
	s.NoError(err)
	s.Equal("c2VjcmV0", ret)
}

func (s *KMSImplementationTestSuite) TestSignError() {
	s.mockAPI.On(
		"Encrypt",
		mock.AnythingOfType("*kms.EncryptInput"),
	).Return((*kms.EncryptOutput)(nil), errors.New("bacon"))
	ret, err := s.sut.Sign("plaintext", nil)
	s.EqualError(err, "key is invalid")
	s.Empty(ret)
}

func (s *KMSImplementationTestSuite) TestVerifyOKWithCache() {
	plaintext, err := base64.StdEncoding.DecodeString("ve/CWUJr0IbREmEIrDlVpsFRZMofWR4Icux8SeRALmo=")
	s.NoError(err)
	s.mockAPI.On(
		"Decrypt",
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
	).Once().Return(&kms.DecryptOutput{
		KeyId:     aws.String(s.keyID),
		Plaintext: plaintext,
	}, nil)
	s.NoError(s.sut.Verify("signing", "YmFjb24K", nil))

	// Ensure cache is warmed.
	s.Equal("YmFjb24K", s.sut.(*kmsClient).cache["signing"])
	s.NoError(s.sut.Verify("signing", "YmFjb24K", nil))
}

func (s *KMSImplementationTestSuite) TestVerifyOKWithoutCache() {
	s.sut = New(s.mockAPI, s.keyID, DisableCache)
	plaintext, err := base64.StdEncoding.DecodeString("ve/CWUJr0IbREmEIrDlVpsFRZMofWR4Icux8SeRALmo=")
	s.NoError(err)
	s.mockAPI.On(
		"Decrypt",
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
	).Twice().Return(&kms.DecryptOutput{
		KeyId:     aws.String(s.keyID),
		Plaintext: plaintext,
	}, nil)
	s.NoError(s.sut.Verify("signing", "YmFjb24K", nil))
	s.Nil(s.sut.(*kmsClient).cache)
	s.NoError(s.sut.Verify("signing", "YmFjb24K", nil))
}

func (s *KMSImplementationTestSuite) TestVerifyDecryptFails() {
	s.mockAPI.
		On("Decrypt", mock.AnythingOfType("*kms.DecryptInput")).
		Return((*kms.DecryptOutput)(nil), errors.New("bacon"))
	s.EqualError(s.sut.Verify("signing", "YmFjb24K", nil), "kms: verification error")
}

func (s *KMSImplementationTestSuite) TestVerifyDifferentKey() {
	s.mockAPI.
		On("Decrypt", mock.AnythingOfType("*kms.DecryptInput")).
		Return(&kms.DecryptOutput{KeyId: aws.String("huh?")}, nil)
	s.EqualError(s.sut.Verify("signing", "YmFjb24K", nil), "key is invalid")
}

func (s *KMSImplementationTestSuite) TestVerifyDoesNotCompare() {
	s.mockAPI.
		On("Decrypt", mock.AnythingOfType("*kms.DecryptInput")).
		Return(&kms.DecryptOutput{KeyId: aws.String(s.keyID), Plaintext: []byte("wrong")}, nil)
	s.EqualError(s.sut.Verify("signing", "YmFjb24K", nil), "kms: verification error")
}

func TestKMSImplementation(t *testing.T) {
	suite.Run(t, new(KMSImplementationTestSuite))
}
