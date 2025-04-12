package jwt

import (
	"CypherJWT/jwt/datastructure"
	"CypherJWT/jwt/keymanager"
	"CypherJWT/jwt/signer"
	"fmt"
)

func CreateSigner(algo datastructure.Algorithm, keymanager keymanager.KeyManager) (signer.Signer, error) {
	switch algo {
	case datastructure.HS256:
		return signer.NewHMACSigner(keymanager), nil
	case datastructure.RS256:
		return signer.NewRSASigner(keymanager), nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algo)
	}
}
