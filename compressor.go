package bacc

import (
	"compress/gzip"
	"github.com/hsinhoyeh/gobzip"
	"io"
	"golang.org/x/crypto/twofish"
	"crypto/aes"
	"compress/bzip2"
)

func newCompressor(writer io.Writer, source *archiveFileWriter) (io.Writer, error) {
	switch source.compressionMethod {
	case COMPMET_GZIP:
		return gzip.NewWriterLevel(writer, gzip.BestCompression)
	case COMPMET_BZIP2:
		return gobzip.NewBzipWriter(writer)

	default:
		return writer, nil
	}
}

func newDecompressor(reader io.Reader, source *fileEntry) (io.Reader, error) {
	size := int64(source.compressedSize)
	if source.encryptionMethod == ENCMET_AES256 {
		size -= aes.BlockSize
	} else if source.encryptionMethod == ENCMET_TWOFISH256 {
		size -= twofish.BlockSize
	}

	switch source.compressionMethod {
	case COMPMET_GZIP:
		return gzip.NewReader(reader)

	case COMPMET_BZIP2:
		return bzip2.NewReader(reader), nil

	default:
		return reader, nil
	}
}
