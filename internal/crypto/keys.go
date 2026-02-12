package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/google/uuid"
)

type KeyData struct {
	KeyID      string `json:"kid"`
	PrivateKey string `json:"privateKey"`
}

type KeyManager struct {
	KeyID      string
	PrivateKey *rsa.PrivateKey
}

func LoadOrGenerate(path string) (*KeyManager, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		var kd KeyData
		if err := json.Unmarshal(data, &kd); err != nil {
			return nil, fmt.Errorf("parse key file: %w", err)
		}
		block, _ := pem.Decode([]byte(kd.PrivateKey))
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block")
		}
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		return &KeyManager{KeyID: kd.KeyID, PrivateKey: key}, nil
	}

	if !os.IsNotExist(err) {
		return nil, err
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	kid := uuid.New().String()
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	kd := KeyData{KeyID: kid, PrivateKey: string(pemData)}
	jsonData, err := json.MarshalIndent(kd, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, jsonData, 0600); err != nil {
		return nil, err
	}

	return &KeyManager{KeyID: kid, PrivateKey: key}, nil
}
