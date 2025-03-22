package jwt

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestPayload_Encode(t *testing.T) {
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

	encodedString, err := payload.Encode()
	if err != nil {
		t.Errorf("Error encoding payload: %v", err)
	}
	if encodedString == "" {
		t.Errorf("Result is empty")
	}

	decodedBytes, err := base64.URLEncoding.DecodeString(encodedString)
	if err != nil {
		t.Errorf("Failed to decode base64 string: %s", err)
	}

	var decodedClaims map[string]interface{}
	err = json.Unmarshal(decodedBytes, &decodedClaims)
	if err != nil {
		t.Errorf("Failed to unmarshal bytes to object: %s", err)
	}

	if !checkEquality(decodedClaims, claims) {
		t.Errorf("Decoded claims does not match original. Got %+v, expected %+v", decodedClaims, claims)
	}
}

func checkEquality(m1 map[string]interface{}, m2 map[string]interface{}) bool {
	json1, _ := json.Marshal(m1)
	json2, _ := json.Marshal(m2)
	return string(json1) == string(json2)
}
