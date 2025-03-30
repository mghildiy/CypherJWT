package signer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

type HMACSigner struct {
	secret []byte
}

func NewHMACSigner(secret []byte) *HMACSigner {
	return &HMACSigner{secret: secret}
}

func (hmacSigner *HMACSigner) Sign(data []byte) (string, error) {
	h := hmac.New(sha256.New, hmacSigner.secret)
	h.Write(data)

	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}
