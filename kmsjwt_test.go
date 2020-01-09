package kmsjwt

import (
	"context"
	"errors"
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

func (m *mockKMS) SignWithContext(ctx aws.Context, input *kms.SignInput, opts ...request.Option) (*kms.SignOutput, error) {
	args := m.Called(ctx, input, opts)
	return args.Get(0).(*kms.SignOutput), args.Error(1)
}

func (m *mockKMS) VerifyWithContext(ctx aws.Context, input *kms.VerifyInput, opts ...request.Option) (*kms.VerifyOutput, error) {
	args := m.Called(ctx, input, opts)
	return args.Get(0).(*kms.VerifyOutput), args.Error(1)
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

func (s *KMSImplementationTestSuite) TestSign_OK() {
	const signingString = "signingString"
	const signature = "signature"

	s.withSignRequest(signingString, signature, nil)

	ret, err := s.sut.Sign(signingString, s.ctx)

	// Ensuring we got the right returns.
	s.Require().NoError(err)
	s.EqualValues(signature, ret)

	// Ensuring that the signature is cached.
	s.ensureCached(signingString, signature)
}

func (s *KMSImplementationTestSuite) TestSign_KMSError() {
	const signingString = "signingString"

	s.withSignRequest(signingString, "signature", errors.New("bacon"))

	ret, err := s.sut.Sign(signingString, s.ctx)

	// Ensuring we got the right returns.
	s.Require().Empty(ret)
	s.EqualError(err, "key is invalid")

	// Ensuring that the signature is not cached.
	s.ensureNotCached(signingString)
}

func (s *KMSImplementationTestSuite) TestSign_KeyNotAContext() {
	ret, err := s.sut.Sign("signingString", "bacon")

	s.Require().Empty(ret)
	s.EqualError(err, "key is not a context")
}

func (s *KMSImplementationTestSuite) TestVerify_CacheHit() {
	const signingString = "signingString"
	const signature = "signature"

	s.sut.(*kmsClient).cache.SetDefault(signingString, []byte(signature))

	// Ensuring that there's no error.
	err := s.sut.Verify(signingString, signature, s.ctx)
	s.Require().NoError(err)
}

func (s *KMSImplementationTestSuite) TestVerify_CacheMiss() {
	const signingString = "signingString"
	const signature = "signature"

	// Ensure that the cache does not contain our entry.
	_, isCached := s.sut.(*kmsClient).cache.Get(signingString)
	s.Require().False(isCached)

	s.withVerifyRequest(signingString, signature, aws.Bool(true), nil)

	// Ensuring that there's no error.
	err := s.sut.Verify(signingString, signature, s.ctx)
	s.Require().NoError(err)

	// Ensuring that the signature is cached.
	s.ensureCached(signingString, signature)
}

func (s *KMSImplementationTestSuite) TestVerify_CacheInvalidType() {
	const signingString = "signingString"
	const signature = "signature"

	// Let's put something of an unexpected type in our cache.
	s.sut.(*kmsClient).cache.SetDefault(signingString, 13)

	s.withVerifyRequest(signingString, signature, aws.Bool(true), nil)

	// Ensuring that there's no error.
	err := s.sut.Verify(signingString, signature, s.ctx)
	s.Require().NoError(err)

	// Ensuring that the correct thing is cached this time.
	s.ensureCached(signingString, signature)
}

func (s *KMSImplementationTestSuite) TestVerify_CacheWrongValue() {
	const signingString = "signingString"
	const signature = "signature"

	// Let's put something of an unexpected type in our cache.
	s.sut.(*kmsClient).cache.SetDefault(signingString, []byte("surprise"))

	s.withVerifyRequest(signingString, signature, aws.Bool(true), nil)

	// Ensuring that there's no error.
	err := s.sut.Verify(signingString, signature, s.ctx)
	s.Require().NoError(err)

	// Ensuring that the correct thing is cached this time.
	s.ensureCached(signingString, signature)
}

func (s *KMSImplementationTestSuite) TestVerify_KMSError() {
	const signingString = "signingString"
	const signature = "signature"

	s.withVerifyRequest(signingString, signature, nil, errors.New("bacon"))

	// Ensuring that the right error is returned.
	err := s.sut.Verify(signingString, signature, s.ctx)
	s.Require().Equal(ErrKmsVerification, err)

	// Ensuring that the signature is not cached.
	s.ensureNotCached(signingString)
}

// According to AWS docs this should never happen, but let's be on the safe
// side.
func (s *KMSImplementationTestSuite) TestVerify_NilSignatureValid() {
	const signingString = "signingString"
	const signature = "signature"

	s.withVerifyRequest(signingString, signature, nil, nil)

	// Ensuring that the right error is returned.
	err := s.sut.Verify(signingString, signature, s.ctx)
	s.Require().Equal(ErrKmsVerification, err)

	// Ensuring that the signature is not cached.
	s.ensureNotCached(signingString)
}

// According to AWS docs this should never happen, but let's be on the safe
// side.
func (s *KMSImplementationTestSuite) TestVerify_SignatureNotValid() {
	const signingString = "signingString"
	const signature = "signature"

	s.withVerifyRequest(signingString, signature, aws.Bool(false), nil)

	// Ensuring that the right error is returned.
	err := s.sut.Verify(signingString, signature, s.ctx)
	s.Require().Equal(ErrKmsVerification, err)

	// Ensuring that the signature is not cached.
	s.ensureNotCached(signingString)
}

func (s *KMSImplementationTestSuite) TestVerify_NotAContext() {
	s.EqualError(s.sut.Verify("signing", "signature", "not context"), "key is not a context")
}

func (s *KMSImplementationTestSuite) ensureCached(signingString, signature string) {
	cachedSignature, isCached := s.sut.(*kmsClient).cache.Get(signingString)
	s.Require().True(isCached)
	s.Require().IsType([]byte(nil), cachedSignature)
	s.Require().EqualValues(signature, cachedSignature)
}

func (s *KMSImplementationTestSuite) ensureNotCached(signingString string) {
	// Ensuring that the signature is not cached.
	_, isCached := s.sut.(*kmsClient).cache.Get(signingString)
	s.Require().False(isCached)
}

func (s *KMSImplementationTestSuite) withSignRequest(signingString, signature string, err error) {
	s.mockAPI.On(
		"SignWithContext",
		s.ctx,
		mock.MatchedBy(func(in interface{}) bool {
			input, ok := in.(*kms.SignInput)

			s.Require().True(ok)
			s.Require().Equal(s.keyID, *input.KeyId)
			s.Require().EqualValues(signingString, input.Message)
			s.Require().Equal("RAW", *input.MessageType)
			s.Require().Equal(kms.SigningAlgorithmSpecRsassaPssSha512, *input.SigningAlgorithm)

			return true
		}),
		[]request.Option(nil),
	).Return(&kms.SignOutput{Signature: []byte(signature)}, err)
}

func (s *KMSImplementationTestSuite) withVerifyRequest(signingString, signature string, valid *bool, err error) {
	s.mockAPI.On(
		"VerifyWithContext",
		s.ctx,
		mock.MatchedBy(func(in interface{}) bool {
			input, ok := in.(*kms.VerifyInput)

			s.Require().True(ok)
			s.Require().Equal(s.keyID, *input.KeyId)
			s.Require().EqualValues(signingString, input.Message)
			s.Require().Equal("RAW", *input.MessageType)
			s.Require().EqualValues(signature, input.Signature)
			s.Require().Equal(kms.SigningAlgorithmSpecRsassaPssSha512, *input.SigningAlgorithm)

			return true
		}),
		[]request.Option(nil),
	).Return(&kms.VerifyOutput{SignatureValid: valid}, err)
}

func TestKMSImplementation(t *testing.T) {
	suite.Run(t, new(KMSImplementationTestSuite))
}
