package jwt

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestSigning(t *testing.T) {
	header := CreateHeader("HS256")
	encodedHeader, err := header.Encode()
	if err != nil {
		t.Fatalf("Error while encdoing header: %s", err)
	}

	claims := map[string]interface{}{
		"iss":   "cypherlabs.example.com",
		"sub":   "user123",
		"aud":   "myapp",
		"exp":   1710780000, // UNIX timestamp (e.g., March 18, 2025)
		"nbf":   1710776400,
		"iat":   1710772800,
		"jti":   "unique-token-id-123",
		"name":  "John Doe",
		"roles": []string{"role1", "role2", "role3"},
	}
	payload := CreatePayload(claims)
	encodedPayload, err := payload.Encode()
	if err != nil {
		t.Fatalf("Error encoding payload: %s", err)
	}

	key := make([]byte, 32)
	_, err = rand.Read(key)
	if err != nil {
		t.Fatalf("Error while generating random key: %s", err)
	}
	secret := base64.StdEncoding.EncodeToString(key)
	jwtToken, err := Sign(header, payload, secret)
	if err != nil {
		t.Fatalf("Error while creating jwt token: %s", err)
	}

	parts := strings.Split(jwtToken, ".")
	if parts[0] != encodedHeader {
		t.Fatalf("JWT header does not match")
	}
	if parts[1] != encodedPayload {
		t.Fatalf("JWT payload does not match")
	}

	expectedSignature := computeHMAC(encodedHeader+"."+encodedPayload, secret)
	if expectedSignature != parts[2] {
		t.Fatalf("JWT signature does not match")
	}

}

func computeHMAC(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))

	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}
