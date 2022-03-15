package kmsjwt

import (
	"context"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"

	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	cache "github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
)

const kmsAlgorighm = "KMS"

// ErrKmsVerification is an error shown when KMS token verification fails.
var ErrKmsVerification = errors.New("kms: verification error")

// ErrInvalidKey indicates taht the key is invalid.
var ErrInvalidKey = errors.New("key is invalid")

type KMSJWT struct {
	kmsiface.KMSAPI

	algorithm         string
	cache             *cache.Cache
	kmsKeyID          string
	withCache         bool
	defaultExpiration time.Duration
	cleanupInterval   time.Duration
	signingAlgorithm  string
}

// New provides a KMS-based implementation of JWT signing method.
func New(client kmsiface.KMSAPI, kmsKeyID string, opts ...Option) *KMSJWT {
	ret := &KMSJWT{
		KMSAPI:            client,
		algorithm:         kmsAlgorighm,
		kmsKeyID:          kmsKeyID,
		withCache:         true,
		defaultExpiration: time.Hour,
		cleanupInterval:   time.Minute,
		signingAlgorithm:  kms.SigningAlgorithmSpecRsassaPssSha512,
	}

	for _, opt := range opts {
		opt(ret)
	}

	if ret.withCache {
		ret.cache = cache.New(ret.defaultExpiration, ret.cleanupInterval)
	}

	return ret
}

func (k *KMSJWT) Alg() string {
	return k.algorithm
}

func (k *KMSJWT) Sign(signingString string, key interface{}) (string, error) {
	ctx, ok := key.(context.Context)
	if !ok {
		return "", errors.New("key is not a context")
	}

	out, err := k.SignWithContext(ctx, &kms.SignInput{
		KeyId:            aws.String(k.kmsKeyID),
		Message:          checksum(signingString),
		MessageType:      aws.String("DIGEST"),
		SigningAlgorithm: aws.String(k.signingAlgorithm),
	})

	if err != nil && errors.Is(err, context.Canceled) {
		return "", err
	} else if err != nil {
		return "", errors.Wrap(err, "key is invalid")
	}

	if k.cache != nil {
		k.cache.SetDefault(signingString, out.Signature)
	}

	return base64.StdEncoding.EncodeToString(out.Signature), nil
}

func (k *KMSJWT) Verify(signingString, stringSignature string, key interface{}) error {
	ctx, ok := key.(context.Context)
	if !ok {
		return errors.New("key is not a context")
	}

	signature, err := base64.StdEncoding.DecodeString(stringSignature)
	if err != nil {
		return errors.New("invalid signature encoding")
	}

	if k.verifyCache(signingString, signature) {
		return nil
	}

	out, err := k.VerifyWithContext(ctx, &kms.VerifyInput{
		KeyId:            aws.String(k.kmsKeyID),
		Message:          checksum(signingString),
		MessageType:      aws.String("DIGEST"),
		Signature:        signature,
		SigningAlgorithm: aws.String(k.signingAlgorithm),
	})

	if err != nil && errors.Is(err, context.Canceled) {
		return err
	} else if err == nil && (out.SignatureValid == nil || !(*out.SignatureValid)) {
		return ErrKmsVerification
	} else if err != nil {
		return errors.Wrap(err, ErrKmsVerification.Error())
	}

	if k.cache != nil {
		k.cache.SetDefault(signingString, signature)
	}

	return nil
}

func (k *KMSJWT) verifyCache(signingString string, providedSignature []byte) bool {
	if k.cache == nil {
		return false
	}

	untypedCached, isCached := k.cache.Get(signingString)
	if !isCached {
		return false
	}

	typedCached, typeOK := untypedCached.([]byte)
	if !typeOK {
		return false
	}

	return subtle.ConstantTimeCompare(typedCached, providedSignature) == 1
}

func checksum(in string) []byte {
	out := sha512.Sum512([]byte(in))
	return out[:]
}
