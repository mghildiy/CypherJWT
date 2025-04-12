package keymanager

import (
	"CypherJWT/jwt/datastructure"
	"fmt"
)

func CreateKeyManager(kmt datastructure.KeyManagerType) (KeyManager, error) {
	switch kmt {
	case datastructure.INMEMORY:
		return NewInMemoryKeyManager(), nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kmt)
	}
}
