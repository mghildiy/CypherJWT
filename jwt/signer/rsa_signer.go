package signer

import (
	"CypherJWT/jwt/datastructure"
	"CypherJWT/jwt/keymanager"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

type RSASigner struct {
	keyManager keymanager.KeyManager
}

func NewRSASigner(keyManager keymanager.KeyManager) Signer {
	return &RSASigner{
		keyManager: keyManager,
	}
}

func (signer *RSASigner) Sign(data []byte) (string, error) {
	privateKey, err := signer.keyManager.GetSecret(datastructure.RS256)
	if err != nil {
		return "", err
	}
	secret, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("invalid key type for RS256")
	}

	// SHA-256 hash of data
	hashed := sha256.Sum256(data)

	// sign the hash with RSA private key
	signature, err := rsa.SignPKCS1v15(rand.Reader, secret, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

var _ Signer = (*RSASigner)(nil)
