package jwt

import (
	"CypherJWT/jwt/datastructure"
	"CypherJWT/jwt/signer"
	"fmt"
)

func CreateSigner(algo datastructure.Algorithm, secret []byte) (signer.Signer, error) {
	switch algo {
	case datastructure.HS256:
		return signer.NewHMACSigner(secret), nil
	default:
		return nil, fmt.Errorf("Unsupported algorithm: %s", algo)
	}
}
