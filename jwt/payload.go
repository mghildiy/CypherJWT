package jwt

import (
	"encoding/base64"
	"encoding/json"
)

type Payload struct {
	Claims map[string]interface{} `json:"claims"`
}

func CreatePayload(claims map[string]interface{}) Payload {
	return Payload{
		Claims: claims,
	}
}

func (p Payload) Encode() (string, error) {
	jsonData, err := json.Marshal(p.Claims)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(jsonData), nil
}
