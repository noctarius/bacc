package bacc

import (
	"io"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"github.com/go-errors/errors"
)

type aesWriter struct {
	writer io.Writer
	iv     []byte
	cfb    cipher.Stream
}

func newAesWriter(writer io.Writer, key []byte) (*aesWriter, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New(err)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, errors.New(err)
	}

	if _, err := writer.Write(iv); err != nil {
		return nil, errors.New(err)
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	return &aesWriter{writer, iv, cfb}, nil
}

func (aw *aesWriter) Close() error {
	if c, success := aw.writer.(io.Closer); success {
		return c.Close()
	}
	return nil
}

func (aw *aesWriter) Write(p []byte) (n int, err error) {
	enc := make([]byte, len(p))
	aw.cfb.XORKeyStream(enc, p)
	return aw.writer.Write(enc)
}

type aesReader struct {
	reader io.Reader
	iv     []byte
	cfb    cipher.Stream
}

func newAesReader(reader io.Reader, key []byte) (io.Reader, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New(err)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := reader.Read(iv); err != nil {
		return nil, errors.New(err)
	}

	cfb := cipher.NewCFBDecrypter(block, iv)
	return &aesReader{reader, iv, cfb}, nil
}

func (ar *aesReader) Read(p []byte) (n int, err error) {
	dec := make([]byte, len(p))
	n, err = ar.reader.Read(p)
	ar.cfb.XORKeyStream(p, dec)
	return n, err
}
