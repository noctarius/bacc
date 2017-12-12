package writer

import (
	"io"
	"crypto/cipher"
	"crypto/rand"
	"golang.org/x/crypto/twofish"
)

type twofishWriter struct {
	writer io.Writer
	iv     []byte
	cfb    cipher.Stream
}

func newTwofishWriter(writer io.Writer, key []byte) (*twofishWriter, error) {
	block, err := twofish.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, twofish.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	if _, err := writer.Write(iv); err != nil {
		return nil, err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	return &twofishWriter{writer, iv, cfb}, nil
}

func (aw *twofishWriter) Close() error {
	if c, success := aw.writer.(io.Closer); success {
		return c.Close()
	}
	return nil
}

func (aw *twofishWriter) Write(p []byte) (n int, err error) {
	enc := make([]byte, len(p))
	aw.cfb.XORKeyStream(enc, p)
	return aw.writer.Write(enc)
}
