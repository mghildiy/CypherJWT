package keymanager

import (
	"CypherJWT/jwt/datastructure"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sync"
)

type InMemoryKeyManager struct {
	mu      sync.RWMutex
	secrets map[datastructure.Algorithm]any
}

func NewInMemoryKeyManager() KeyManager {
	return &InMemoryKeyManager{
		secrets: make(map[datastructure.Algorithm]any),
	}
}

func (i *InMemoryKeyManager) GetSecret(algorithm datastructure.Algorithm) (any, error) {
	i.mu.RLock()
	secret, exists := i.secrets[algorithm]
	if exists {
		i.mu.RUnlock()
		return secret, nil
	}
	i.mu.RUnlock()

	i.mu.Lock()
	defer i.mu.Unlock()

	switch algorithm {
	case datastructure.HS256:
		key := make([]byte, 32)
		_, err := rand.Read(key)
		if err != nil {
			return nil, fmt.Errorf("Encountered a problem while generating HMAC key: %v", err)
		}
		i.secrets[algorithm] = key

		return key, nil
	case datastructure.RS256:
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("Encountered a problem while generating RSA key: %v", err)
		}
		i.secrets[algorithm] = privateKey

		return privateKey, nil
	}

	return nil, fmt.Errorf("Unsupported algorithm %v", algorithm)
}
