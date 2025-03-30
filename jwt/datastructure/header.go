package datastructure

import (
	"encoding/base64"
	"encoding/json"
)

type Header struct {
	Algo Algorithm `json:"alg"`
	Type string    `json:"typ"`
}

func CreateHeader(alg Algorithm) Header {
	return Header{
		Algo: alg,
		Type: "JWT",
	}
}

func (h Header) Encode() (string, error) {
	jsonData, err := json.Marshal(h)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(jsonData), nil
}
