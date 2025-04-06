package signer

import (
	"CypherJWT/jwt/datastructure"
	"CypherJWT/jwt/keymanager"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

type HMACSigner struct {
	keyManager keymanager.KeyManager
}

func NewHMACSigner(keyManager keymanager.KeyManager) Signer {
	return &HMACSigner{keyManager: keyManager}
}

func (signer *HMACSigner) Sign(data []byte) (string, error) {
	secret, err := signer.keyManager.GetSecret(datastructure.HS256)
	if err != nil {
		return "", err
	}
	secretByte, ok := secret.([]byte)
	if !ok {
		return "", errors.New("key is not []byte")
	}
	h := hmac.New(sha256.New, secretByte)
	h.Write(data)

	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

var _ Signer = (*HMACSigner)(nil)
