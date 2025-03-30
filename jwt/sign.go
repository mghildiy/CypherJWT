package jwt

import (
	"CypherJWT/jwt/datastructure"
	"CypherJWT/jwt/signer"
	"fmt"
)

func Sign(signer signer.Signer, header datastructure.Header, payload datastructure.Payload) (string, error) {
	encodedHeader, err := header.Encode()
	if err != nil {
		return "", err
	}

	encodedPayload, err := payload.Encode()
	if err != nil {
		return "", err
	}

	data := fmt.Sprintf("%s.%s", encodedHeader, encodedPayload)
	signature, err := signer.Sign([]byte(data))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s.%s.%s", encodedHeader, encodedPayload, signature), nil
}
