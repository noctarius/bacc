package bacc

import (
	"io"
	"crypto/cipher"
	"crypto/rand"
	"golang.org/x/crypto/twofish"
	"github.com/go-errors/errors"
)

type twofishWriter struct {
	writer io.Writer
	iv     []byte
	cfb    cipher.Stream
}

func newTwofishWriter(writer io.Writer, key []byte) (*twofishWriter, error) {
	block, err := twofish.NewCipher(key)
	if err != nil {
		return nil, errors.New(err)
	}

	iv := make([]byte, twofish.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, errors.New(err)
	}

	if _, err := writer.Write(iv); err != nil {
		return nil, errors.New(err)
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	return &twofishWriter{writer, iv, cfb}, nil
}

func (tw *twofishWriter) Close() error {
	if c, success := tw.writer.(io.Closer); success {
		return c.Close()
	}
	return nil
}

func (tw *twofishWriter) Write(p []byte) (n int, err error) {
	enc := make([]byte, len(p))
	tw.cfb.XORKeyStream(enc, p)
	return tw.writer.Write(enc)
}

type twofishReader struct {
	reader io.Reader
	iv     []byte
	cfb    cipher.Stream
}

func newTwofishReader(reader io.Reader, key []byte) (io.Reader, error) {
	block, err := twofish.NewCipher(key)
	if err != nil {
		return nil, errors.New(err)
	}

	iv := make([]byte, twofish.BlockSize)
	if _, err := reader.Read(iv); err != nil {
		return nil, errors.New(err)
	}

	cfb := cipher.NewCFBDecrypter(block, iv)
	return &twofishReader{reader, iv, cfb}, nil
}

func (tr *twofishReader) Read(p []byte) (n int, err error) {
	dec := make([]byte, len(p))
	n, err = tr.reader.Read(p)
	tr.cfb.XORKeyStream(p, dec)
	return n, err
}
