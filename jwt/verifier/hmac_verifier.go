package verifier

import (
	"CypherJWT/jwt/signer"
	"crypto/hmac"
	"fmt"
	"strings"
)

type HMACVerifier struct {
	secret []byte
}

func NewHMACVerifier(secret []byte) *HMACVerifier {
	return &HMACVerifier{
		secret: secret,
	}
}

func (hmacVerifier *HMACVerifier) Verify(token string) (bool, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false, fmt.Errorf("invalid token")
	}

	encodedHeader := parts[0]
	encodedPayload := parts[1]
	hmacSigner := signer.NewHMACSigner(hmacVerifier.secret)
	data := fmt.Sprintf("%s.%s", encodedHeader, encodedPayload)
	validToken, err := hmacSigner.Sign([]byte(data))
	if err != nil {
		return false, err
	}

	if !hmac.Equal([]byte(parts[2]), []byte(validToken)) {
		return false, fmt.Errorf("invalid token")
	}

	payLoad, err := parsePayload(encodedPayload)
	if err != nil {
		return false, err
	}
	_, err = validateClaims(payLoad)
	if err != nil {
		return false, fmt.Errorf("invalid claims: %w", err)
	}

	return true, nil
}
