package bacc

import (
	"crypto"
	"io/ioutil"
	"encoding/pem"
	"crypto/x509"
	"errors"
	"crypto/rsa"
	"crypto/sha512"
	"io"
	"crypto/rand"
	"hash"
)

type Signer interface {
	Sign(reader io.Reader, size int64, progress ProgressCallback) ([]byte, error)
}

type Verifier interface {
	Verify(reader io.Reader, size int64, signature []byte, progress ProgressCallback) error
}

type rsaPrivateKey struct {
	*rsa.PrivateKey
}

type rsaPublicKey struct {
	*rsa.PublicKey
}

func LoadKeyForSigning(keyPath string) (Signer, error) {
	data, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKey(data)
}

func LoadKeyForVerifying(keyPath string) (Verifier, error) {
	data, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(data)
}

func ParsePrivateKey(data []byte) (Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		rsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return &rsaPrivateKey{rsa}, nil
	default:
		return nil, errors.New("given key is not a RSA private key")
	}
}

func ParsePublicKey(data []byte) (Verifier, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		if pub, success := key.(*rsa.PublicKey); success {
			return &rsaPublicKey{pub}, nil
		}
	}
	return nil, errors.New("given key is not a RSA public key")
}

func (rpk *rsaPrivateKey) Sign(reader io.Reader, size int64, progress ProgressCallback) ([]byte, error) {
	hash, err := generateSigningHash(reader, size, progress, func() hash.Hash { return sha512.New() })

	if err != nil {
		return nil, err
	}
	return rsa.SignPKCS1v15(rand.Reader, rpk.PrivateKey, crypto.SHA512, hash)
}

func (rpk *rsaPublicKey) Verify(reader io.Reader, size int64, signature []byte, progress ProgressCallback) error {
	hash, err := generateSigningHash(reader, size, progress, func() hash.Hash { return sha512.New() })

	if err != nil {
		return err
	}
	return rsa.VerifyPKCS1v15(rpk.PublicKey, crypto.SHA512, hash, signature)
}
