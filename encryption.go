package bacc

import (
	"io"
	"github.com/go-errors/errors"
)

func createEncryptor(writer io.Writer, source *archiveFileWriter, key []byte) (io.Writer, error) {
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

func createDecryptor(reader io.Reader, source *fileEntry, key []byte) (io.Reader, error) {
	baseOffset := int64(source.contentOffset)
	size := int64(source.compressedSize)

	switch source.encryptionMethod {
	case ENCMET_AES256:
		return newAesReader(reader, key)

	case ENCMET_TWOFISH256:
		return newTwofishReader(reader, baseOffset, size, key)

	case ENCMET_RSA_PRIVATE:
		// Unimplemented yet
		return &relativeReaderAt{reader, baseOffset}, nil

	case ENCMET_RSA_PUBLIC:
		// Unimplemented yet
		return &relativeReaderAt{reader, baseOffset}, nil

	default:
		return &relativeReaderAt{reader, baseOffset}, nil
	}
}
