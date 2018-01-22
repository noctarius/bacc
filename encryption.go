package bacc

import (
	"io"
	"github.com/go-errors/errors"
)

func newEncryptor(writer io.Writer, source *archiveFileWriter, key []byte) (io.Writer, error) {
	switch source.encryptionMethod {
	case ENCMET_AES256:
		w, err := newAesWriter(writer, key)
		if err != nil {
			return nil, errors.New(err)
		}
		return w, nil

	case ENCMET_TWOFISH256:
		w, err := newTwofishWriter(writer, key)
		if err != nil {
			return nil, errors.New(err)
		}
		return w, nil

	case ENCMET_RSA_PRIVATE:
		// Unimplemented yet
		return writer, nil

	case ENCMET_RSA_PUBLIC:
		// Unimplemented yet
		return writer, nil

	default:
		return writer, nil
	}
}

func newDecryptor(reader io.Reader, source *fileEntry, key []byte) (io.Reader, error) {
	switch source.encryptionMethod {
	case ENCMET_AES256:
		return newAesReader(reader, key)

	case ENCMET_TWOFISH256:
		return newTwofishReader(reader, key)

	case ENCMET_RSA_PRIVATE:
		// Unimplemented yet
		return reader, nil

	case ENCMET_RSA_PUBLIC:
		// Unimplemented yet
		return reader, nil
	}

	return reader, nil
}
