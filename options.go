package kmsjwt

import "time"

// Option is a function that modifies the way the verification method works.
type Option func(*KMSJWT)

// DisableCache disables cache on the client (on by default).
func DisableCache(k *KMSJWT) {
	k.withCache = false
}

func WithAlgorithm(algorithm string) Option {
	return func(k *KMSJWT) {
		k.algorithm = algorithm
	}
}

// WithDefaultExpiration changes the default key expiration if the cache is
// "on". By default, cache expires after an hour.
func WithDefaultExpiration(defaultExpiration time.Duration) Option {
	return func(k *KMSJWT) {
		k.defaultExpiration = defaultExpiration
	}
}

// WithCleanupInterval changes the key cleanup interval if the cache is "on". By
// default, it's one minute.
func WithCleanupInterval(cleanupInterval time.Duration) Option {
	return func(k *KMSJWT) {
		k.cleanupInterval = cleanupInterval
	}
}

// WithSigningAlgorithm changes the algorighm used to sign and verify tokens. By
// default, "RSAES_OAEP_SHA_256" is used.
func WithSigningAlgorithm(algorighm string) Option {
	return func(k *KMSJWT) {
		k.signingAlgorithm = algorighm
	}
}
