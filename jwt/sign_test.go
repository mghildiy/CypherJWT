package jwt

import (
	"CypherJWT/jwt/datastructure"
	"CypherJWT/jwt/keymanager"
	"CypherJWT/jwt/signer"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func createHeader(signingAlgo datastructure.Algorithm) datastructure.Header {
	return datastructure.CreateHeader(signingAlgo)
}

func createPayload() datastructure.Payload {
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

	return datastructure.CreatePayload(claims)
}

func verify(toVerify string, against string, subpart string, t *testing.T) {
	if toVerify != against {
		t.Fatalf("%v doesn't match. Actual:%v, Computed:%v", subpart, against, toVerify)
	}
}

func verifyParts(parts []string, header datastructure.Header, payload datastructure.Payload, t *testing.T) {
	encodedHeader, _ := header.Encode()
	encodedPayload, _ := payload.Encode()
	verify(parts[0], encodedHeader, "Header", t)
	verify(parts[1], encodedPayload, "Payload", t)
}

func TestRSASigning(t *testing.T) {
	// prepare test data
	header := createHeader(datastructure.RS256)
	payload := createPayload()
	keyManager, err := keymanager.CreateKeyManager(datastructure.INMEMORY)
	if err != nil {
		t.Fatalf("Error creating key manager: %s", err)
	}
	rsaSigner, err := signer.CreateSigner(datastructure.RS256, keyManager)
	if err != nil {
		t.Fatalf("Error creating RSASigner: %s", err)
	}

	// invoke unit to test
	jwtToken, err := Sign(rsaSigner, header, payload)
	if err != nil {
		t.Fatalf("Error while creating jwt token: %s", err)
	}

	// validation
	parts := strings.Split(jwtToken, ".")
	encodedHeader, err := header.Encode()
	encodedPayload, err := payload.Encode()
	verifyParts(parts, header, payload, t)
	keyAny, err := keyManager.GetSecret(datastructure.RS256)
	if err != nil {
		t.Fatalf("Error getting key from secret manager: %s", err)
	}
	keyFromManager := keyAny.(*rsa.PrivateKey)
	expectedSignature, err := computeRSA(encodedHeader+"."+encodedPayload, keyFromManager)
	if err != nil {
		t.Fatalf("Error computing RSA signature: %s", err)
	}
	if expectedSignature != parts[2] {
		t.Fatalf("JWT signature does not match")
	}
}

func TestHMACSigning(t *testing.T) {
	// prepare test data
	header := createHeader(datastructure.HS256)
	payload := createPayload()
	keyManager, err := keymanager.CreateKeyManager(datastructure.INMEMORY)
	if err != nil {
		t.Fatalf("Error creating key manager: %v", err)
	}
	hmacSigner, err := signer.CreateSigner(datastructure.HS256, keyManager)
	if err != nil {
		t.Fatalf("Error creating HMACSigner: %s", err)
	}

	// invoke unit to test
	jwtToken, err := Sign(hmacSigner, header, payload)
	if err != nil {
		t.Fatalf("Error while creating jwt token: %s", err)
	}

	// validation
	parts := strings.Split(jwtToken, ".")
	encodedHeader, err := header.Encode()
	encodedPayload, err := payload.Encode()
	verifyParts(parts, header, payload, t)
	keyAny, err := keyManager.GetSecret(datastructure.HS256)
	if err != nil {
		t.Fatalf("Error getting key from secret manager: %s", err)
	}
	keyFromManager := keyAny.([]byte)
	expectedSignature := computeHMAC(encodedHeader+"."+encodedPayload, keyFromManager)
	if expectedSignature != parts[2] {
		t.Fatalf("JWT signature does not match")
	}
}

func computeRSA(data string, secret *rsa.PrivateKey) (string, error) {
	hashed := sha256.Sum256([]byte(data))
	signature, err := rsa.SignPKCS1v15(rand.Reader, secret, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(signature), nil
}

func computeHMAC(data string, secret []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(data))

	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
