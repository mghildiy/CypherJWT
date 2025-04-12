package datastructure

type KeyManagerType string

const (
	INMEMORY  KeyManagerType = "IN_MEMORY"
	FILEBASED KeyManagerType = "FILE_BASED"
	VAULT     KeyManagerType = "VAULT"
)

func (kmt KeyManagerType) isValid() bool {
	return kmt == INMEMORY || kmt == FILEBASED || kmt == VAULT
}
