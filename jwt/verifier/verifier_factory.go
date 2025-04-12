package verifier

import (
	"CypherJWT/jwt/datastructure"
	"CypherJWT/jwt/keymanager"
	"fmt"
)

func CreateVerifier(algo datastructure.Algorithm, km keymanager.KeyManager, issuer string, audience string) (Verifier, error) {
	switch algo {
	case datastructure.HS256:
		return NewHMACVerifier(km, issuer, audience), nil
	case datastructure.RS256:
		// TODO: Add RSA signer & verifier when available
		return nil, fmt.Errorf("RS256 not implemented yet")
	case datastructure.ES256:
		// TODO: Add ECDSA signer & verifier when available
		return nil, fmt.Errorf("ES256 not implemented yet")
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algo)
	}
}
