package writer

import (
	"io"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

type aesWriter struct {
	writer io.Writer
	iv     []byte
	cfb    cipher.Stream
}

func newAesWriter(writer io.Writer, key []byte) (*aesWriter, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	if _, err := writer.Write(iv); err != nil {
		return nil, err
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
