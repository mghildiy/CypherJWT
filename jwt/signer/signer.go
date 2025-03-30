package signer

type Signer interface {
	Sign(data []byte) (string, error)
}
