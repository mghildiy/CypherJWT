package jwt

import (
	"CypherJWT/jwt/datastructure"
	"CypherJWT/jwt/keymanager"
	"fmt"
)

func CreateKeyManager(kmt datastructure.KeyManagerType) (keymanager.KeyManager, error) {
	switch kmt {
	case datastructure.INMEMORY:
		return keymanager.NewInMemoryKeyManager(), nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kmt)
	}
}
