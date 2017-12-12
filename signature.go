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
	Sign(reader io.ReaderAt, signatureOffset int64) ([]byte, error)
}

type Verifier interface {
	Verify(reader io.ReaderAt, signatureOffset int64, signature []byte) error
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
	return parsePrivateKey(data)
}

func LoadKeyForVerifying(keyPath string) (Verifier, error) {
	data, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	return parsePublicKey(data)
}

func parsePrivateKey(data []byte) (Signer, error) {
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

func parsePublicKey(data []byte) (Verifier, error) {
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

func (rpk *rsaPrivateKey) Sign(reader io.ReaderAt, signatureOffset int64) ([]byte, error) {
	hash, err := generateHash(reader, signatureOffset, func() hash.Hash { return sha512.New() })
	if err != nil {
		return nil, err
	}
	return rsa.SignPKCS1v15(rand.Reader, rpk.PrivateKey, crypto.SHA512, hash)
}

func (rpk *rsaPublicKey) Verify(reader io.ReaderAt, signatureOffset int64, signature []byte) error {
	hash, err := generateHash(reader, signatureOffset, func() hash.Hash { return sha512.New() })
	if err != nil {
		return err
	}
	return rsa.VerifyPKCS1v15(rpk.PublicKey, crypto.SHA512, hash, signature)
}

func generateHash(reader io.ReaderAt, signatureOffset int64, hasherFactory func() hash.Hash) ([]byte, error) {
	hasher := hasherFactory()
	buffer := make([]byte, 1024)

	offset := int64(0)
	for ; ; {
		bytes, err := reader.ReadAt(buffer, offset)
		if err != nil && err != io.EOF {
			return nil, err
		}

		breakOut := false
		if offset+int64(bytes) >= signatureOffset {
			bytes = int(signatureOffset - offset)
			breakOut = true
		}

		hasher.Write(buffer[:bytes])
		offset += int64(bytes)

		if err == io.EOF || breakOut {
			break
		}
	}

	return hasher.Sum(nil), nil
}
