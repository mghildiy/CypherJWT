package service

import (
	"CypherJWT/jwt/datastructure"
	"CypherJWT/jwt/keymanager"
	"CypherJWT/jwt/signer"
	"CypherJWT/jwt/verifier"
	"fmt"
)

type Config struct {
	Algorithm      datastructure.Algorithm
	KeyManagerType datastructure.KeyManagerType
	issuer         string
	audience       string
}

func NewJWTService(cfg Config) (*JWTService, error) {
	if !cfg.Algorithm.IsValid() {
		return nil, fmt.Errorf("unsupported algorithm: %s", cfg.Algorithm)
	}
	if !cfg.KeyManagerType.IsValid() {
		return nil, fmt.Errorf("unsupported key manager type: %s", cfg.KeyManagerType)
	}
	keyManager, err := keymanager.CreateKeyManager(cfg.KeyManagerType)
	if err != nil {
		return nil, err
	}
	signer, err := signer.CreateSigner(cfg.Algorithm, keyManager)
	verifier, err := verifier.CreateVerifier(cfg.Algorithm, keyManager, cfg.issuer, cfg.audience)
	return &JWTService{
		algo:     cfg.Algorithm,
		signer:   signer,
		verifier: verifier,
	}, nil
}

type JWTService struct {
	algo     datastructure.Algorithm
	signer   signer.Signer
	verifier verifier.Verifier
}

func (s *JWTService) Sign(payload datastructure.Payload) (string, error) {
	header := datastructure.Header{
		Algo: s.algo,
		Type: "JWT",
	}
	encodedHeader, err := header.Encode()
	if err != nil {
		return "", err
	}

	encodedPayload, err := payload.Encode()
	if err != nil {
		return "", err
	}

	data := fmt.Sprintf("%s.%s", encodedHeader, encodedPayload)
	return s.signer.Sign([]byte(data))
}

func (s *JWTService) Verify(token string) (bool, error) {
	return s.verifier.Verify(token)
}
