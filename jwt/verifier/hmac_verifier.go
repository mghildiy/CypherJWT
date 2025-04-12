package verifier

import (
	"CypherJWT/jwt/keyManager"
	"CypherJWT/jwt/signer"
	"crypto/hmac"
	"fmt"
)

type HMACVerifier struct {
	keyManager keymanager.KeyManager
	issuer     string
	audience   string
}

func NewHMACVerifier(keyManager keymanager.KeyManager, issuer, audience string) *HMACVerifier {
	return &HMACVerifier{
		keyManager: keyManager,
		issuer:     issuer,
		audience:   audience,
	}
}

func (hmacVerifier *HMACVerifier) Verify(token string) (bool, error) {
	parts, err := extractParts(token)
	if err != nil {
		return false, fmt.Errorf("invalid token: %w", err)
	}

	encodedHeader := parts[0]
	encodedPayload := parts[1]
	hmacSigner := signer.NewHMACSigner(hmacVerifier.keyManager)
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
	_, err = validateClaims(payLoad, hmacVerifier.issuer, hmacVerifier.audience)
	if err != nil {
		return false, fmt.Errorf("invalid claims: %w", err)
	}

	return true, nil
}
