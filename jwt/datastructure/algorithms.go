package datastructure

type Algorithm string

const (
	HS256 Algorithm = "HS256"
	RS256 Algorithm = "RS256"
	ES256 Algorithm = "ES256"
)

func (algo Algorithm) isValid() bool {
	return algo == HS256 || algo == RS256 || algo == ES256
}
