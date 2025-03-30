package jwt

import (
	"CypherJWT/jwt/datastructure"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestSigning(t *testing.T) {
	header := datastructure.CreateHeader(datastructure.HS256)
	claims := map[string]interface{}{
		"iss":   "cypherlabs.example.com",
		"sub":   "user123",
		"aud":   "myapp",
		"exp":   1710780000,
		"nbf":   1710776400,
		"iat":   1710772800,
		"jti":   "unique-token-id-123",
		"name":  "John Doe",
		"roles": []string{"role1", "role2", "role3"},
	}
	payload := datastructure.CreatePayload(claims)
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Error generating random key: %v", err)
	}
	hmacSigner, err := CreateSigner(datastructure.HS256, key)
	if err != nil {
		t.Fatalf("Error creating HMACSigner: %s", err)
	}

	jwtToken, err := Sign(hmacSigner, header, payload)
	if err != nil {
		t.Fatalf("Error while creating jwt token: %s", err)
	}

	parts := strings.Split(jwtToken, ".")
	encodedHeader, err := header.Encode()
	if err != nil {
		t.Fatalf("Error encoding header: %s", err)
	}
	if parts[0] != encodedHeader {
		t.Fatalf("JWT header does not match")
	}
	encodedPayload, err := payload.Encode()
	if err != nil {
		t.Fatalf("Error encoding payload: %s", err)
	}
	if parts[1] != encodedPayload {
		t.Fatalf("JWT payload does not match")
	}
	expectedSignature := computeHMAC(encodedHeader+"."+encodedPayload, key)
	if expectedSignature != parts[2] {
		t.Fatalf("JWT signature does not match")
	}
}

func computeHMAC(data string, secret []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(data))

	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
