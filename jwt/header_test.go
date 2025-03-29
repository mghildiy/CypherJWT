package jwt

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestHeader_Encode(t *testing.T) {
	header := CreateHeader("HS256")

	encodedString, err := header.Encode()

	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	if encodedString == "" {
		t.Fatal("Unexpected empty result")
	}

	decodedBytes, err := base64.RawURLEncoding.DecodeString(encodedString)
	if err != nil {
		t.Errorf("Failed to decode base64 string: %s", err)
	}

	var decodedHeader Header
	err = json.Unmarshal(decodedBytes, &decodedHeader)
	if err != nil {
		t.Errorf("Failed to unmarshal bytes to object: %s", err)
	}

	if decodedHeader != header {
		t.Errorf("Decoded header does not match original. Got %+v, expected %+v", decodedHeader, header)
	}

}
