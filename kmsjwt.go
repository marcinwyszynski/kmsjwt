package kmsjwt

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
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
	signingAlgorithm  string
}

// New provides a KMS-based implementation of JWT signing method.
func New(client kmsiface.KMSAPI, kmsKeyID string, opts ...Option) jwt.SigningMethod {
	ret := &kmsClient{
		KMSAPI:            client,
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

func (k *kmsClient) Alg() string {
	return kmsAlgorighm
}

func (k *kmsClient) Sign(signingString string, key interface{}) (string, error) {
	ctx, ok := key.(context.Context)
	if !ok {
		return "", errors.New("key is not a context")
	}

	out, err := k.SignWithContext(ctx, &kms.SignInput{
		KeyId:            aws.String(k.kmsKeyID),
		Message:          []byte(signingString),
		MessageType:      aws.String("RAW"),
		SigningAlgorithm: aws.String(k.signingAlgorithm),
	})

	if err != nil && errors.Is(err, context.Canceled) {
		return "", err
	} else if err != nil {
		return "", jwt.ErrInvalidKey
	}

	if k.cache != nil {
		k.cache.SetDefault(signingString, out.Signature)
	}

	return base64.StdEncoding.EncodeToString(out.Signature), nil
}

func (k *kmsClient) Verify(signingString, stringSignature string, key interface{}) error {
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
		Message:          []byte(signingString),
		MessageType:      aws.String("RAW"),
		Signature:        signature,
		SigningAlgorithm: aws.String(k.signingAlgorithm),
	})

	if err != nil && errors.Is(err, context.Canceled) {
		return err
	} else if err != nil || out.SignatureValid == nil || !(*out.SignatureValid) {
		return ErrKmsVerification
	}

	if k.cache != nil {
		k.cache.SetDefault(signingString, signature)
	}

	return nil
}

func (k *kmsClient) verifyCache(signingString string, providedSignature []byte) bool {
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
