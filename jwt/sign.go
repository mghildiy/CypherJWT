package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

func Sign(header Header, payload Payload, secret string) (string, error) {
	encodedHeader, err := header.Encode()
	if err != nil {
		return "", err
	}

	encodedPayload, err := payload.Encode()
	if err != nil {
		return "", err
	}

	data := fmt.Sprintf("%s.%s", encodedHeader, encodedPayload)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return fmt.Sprintf("%s.%s.%s", encodedHeader, encodedPayload, signature), nil

}
