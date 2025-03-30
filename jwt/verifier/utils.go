package verifier

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

func parsePayload(encodedPayload string) (map[string]interface{}, error) {
	decodedBytes, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, err
	}

	claims := map[string]interface{}{}
	err = json.Unmarshal(decodedBytes, &claims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse payload: %w", err)
	}

	return claims, nil
}

func validateClaims(claims map[string]interface{}) (bool, error) {
	currentTime := float64(time.Now().Unix())
	if exp, ok := claims["exp"].(float64); ok {
		if exp < currentTime {
			return false, errors.New("token has expired")
		}
	}
	if nbf, ok := claims["nbf"].(float64); ok {
		if nbf > currentTime {
			return false, fmt.Errorf("token is not yet valid")
		}
	}
	if iat, ok := claims["iat"].(float64); ok {
		if iat > currentTime {
			return false, fmt.Errorf("token issued in the future")
		}
	}

	return true, nil
}
