package kmsjwt

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"github.com/dgrijalva/jwt-go"
)

const kmsAlgorighm = "KMS"

// ErrKmsVerification is an error shown when KMS token verification fails.
var ErrKmsVerification = errors.New("kms: verification error")

type kmsClient struct {
	kmsiface.KMSAPI
	cache    map[string]string
	kmsKeyID string
}

// Option is a function that modifies the way the verification method works.
type Option func(*kmsClient)

// DisableCache disables cache on the client (on by default).
func DisableCache(k *kmsClient) {
	k.cache = nil
}

// New provides a KMS-based implementation of JWT signing method.
func New(client kmsiface.KMSAPI, kmsKeyID string, opts ...Option) jwt.SigningMethod {
	ret := &kmsClient{
		KMSAPI:   client,
		cache:    make(map[string]string),
		kmsKeyID: kmsKeyID,
	}
	for _, opt := range opts {
		opt(ret)
	}
	return ret
}

func (k *kmsClient) Alg() string {
	return kmsAlgorighm
}

func (k *kmsClient) Sign(signingString string, _ interface{}) (string, error) {
	checksum := sha256Checksum(signingString)
	input := &kms.EncryptInput{KeyId: aws.String(k.kmsKeyID), Plaintext: checksum}
	output, err := k.Encrypt(input)
	if err != nil {
		return "", jwt.ErrInvalidKey
	}
	return base64.StdEncoding.EncodeToString(output.CiphertextBlob), nil
}

func (k *kmsClient) Verify(signingString, providedSignature string, _ interface{}) error {
	checksum := sha256Checksum(signingString)
	if k.verifyCache(signingString, providedSignature, checksum) {
		return nil
	}
	ciphertext, err := base64.StdEncoding.DecodeString(providedSignature)
	if err != nil {
		return err
	}
	output, err := k.Decrypt(&kms.DecryptInput{CiphertextBlob: ciphertext})
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
		k.cache[signingString] = providedSignature
	}
	return nil
}

func (k *kmsClient) verifyCache(signingString, providedSignature string, checksum []byte) bool {
	if k.cache == nil {
		return false
	}
	signature, ok := k.cache[signingString]
	if !ok || signature != providedSignature {
		return false
	}
	subtle.ConstantTimeCompare(checksum, checksum)
	return true
}

func sha256Checksum(signingString string) []byte {
	ret := sha256.Sum256([]byte(signingString))
	return ret[:]
}
