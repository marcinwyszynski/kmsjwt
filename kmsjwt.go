package kmsjwt

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"github.com/dgrijalva/jwt-go"
	cache "github.com/patrickmn/go-cache"
)

const kmsAlgorighm = "KMS"

// ErrKmsVerification is an error shown when KMS token verification fails.
var ErrKmsVerification = errors.New("kms: verification error")

type kmsClient struct {
	kmsiface.KMSAPI
	cache             *cache.Cache
	kmsKeyID          string
	withCache         bool
	defaultExpiration time.Duration
	cleanupInterval   time.Duration
}

// New provides a KMS-based implementation of JWT signing method.
func New(client kmsiface.KMSAPI, kmsKeyID string, opts ...Option) jwt.SigningMethod {
	ret := &kmsClient{
		KMSAPI:            client,
		kmsKeyID:          kmsKeyID,
		withCache:         true,
		defaultExpiration: time.Hour,
		cleanupInterval:   time.Minute,
	}
	for _, opt := range opts {
		opt(ret)
	}
	if ret.withCache {
		ret.cache = cache.New(ret.defaultExpiration, ret.cleanupInterval)
	}
	return ret
}

func (k *kmsClient) Alg() string {
	return kmsAlgorighm
}

func (k *kmsClient) Sign(signingString string, key interface{}) (string, error) {
	ctx, ok := key.(context.Context)
	if !ok {
		return "", errors.New("key is not a context")
	}
	checksum := sha256Checksum(signingString)
	input := &kms.EncryptInput{KeyId: aws.String(k.kmsKeyID), Plaintext: checksum}
	output, err := k.EncryptWithContext(ctx, input)
	if err != nil {
		return "", jwt.ErrInvalidKey
	}
	return base64.StdEncoding.EncodeToString(output.CiphertextBlob), nil
}

func (k *kmsClient) Verify(signingString, providedSignature string, key interface{}) error {
	ctx, ok := key.(context.Context)
	if !ok {
		return errors.New("key is not a context")
	}
	checksum := sha256Checksum(signingString)
	if k.verifyCache(signingString, providedSignature, checksum) {
		return nil
	}
	ciphertext, err := base64.StdEncoding.DecodeString(providedSignature)
	if err != nil {
		return err
	}
	output, err := k.DecryptWithContext(ctx, &kms.DecryptInput{CiphertextBlob: ciphertext})
	if err != nil {
		return ErrKmsVerification
	}
	// The output keyID is the full ARN, the internal ID is just the key ID.
	if !strings.HasSuffix(*output.KeyId, k.kmsKeyID) {
		return jwt.ErrInvalidKey
	}
	if subtle.ConstantTimeCompare(output.Plaintext, checksum) != 1 {
		return ErrKmsVerification
	}
	if k.cache != nil {
		k.cache.SetDefault(signingString, providedSignature)
	}
	return nil
}

func (k *kmsClient) verifyCache(signingString, providedSignature string, checksum []byte) bool {
	if k.cache == nil {
		return false
	}
	signature, ok := k.cache.Get(signingString)
	if !ok || signature.(string) != providedSignature {
		return false
	}
	subtle.ConstantTimeCompare(checksum, checksum)
	return true
}

func sha256Checksum(signingString string) []byte {
	ret := sha256.Sum256([]byte(signingString))
	return ret[:]
}
