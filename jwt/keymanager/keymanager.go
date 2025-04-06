package keymanager

import "CypherJWT/jwt/datastructure"

type KeyManager interface {
	GetSecret(algorithm datastructure.Algorithm) (any, error)
}
