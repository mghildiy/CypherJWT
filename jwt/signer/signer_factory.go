package signer

import (
	"CypherJWT/jwt/datastructure"
	"CypherJWT/jwt/keymanager"
	"fmt"
)

func CreateSigner(algo datastructure.Algorithm, keymanager keymanager.KeyManager) (Signer, error) {
	switch algo {
	case datastructure.HS256:
		return NewHMACSigner(keymanager), nil
	case datastructure.RS256:
		return NewRSASigner(keymanager), nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algo)
	}
}
