package verifier

type Verifier interface {
	Verify(token string) (bool, error)
}
