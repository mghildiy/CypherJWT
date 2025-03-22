package jwt

import (
	"encoding/base64"
	"encoding/json"
)

type Header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

func CreateHeader(alg string) Header {
	return Header{
		Algorithm: alg,
		Type:      "JWT",
	}
}

func (h Header) Encode() (string, error) {
	jsonData, err := json.Marshal(h)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(jsonData), nil
}
