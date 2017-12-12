package writer

import (
	"github.com/ugorji/go/codec"
	"bytes"
	"github.com/relations-one/bacc"
	"io"
	"hash"
)

const symKey = "7708398af3d5726a3918120f62a589e89770f96a6fb83eff0612aa531c8395b8"
const keyHash = "206bca26b1158ab1dfc7416e8016ad1594d8a0be0060b7728f2e48affc7300d5"

type encryptionConfig struct {
	encryptionMethod      bacc.EncryptionMethod
	encryptionKey         string
	encryptionCertificate string
}

type signatureConfig struct {
	signatureMethod      bacc.SignatureMethod
	signatureCertificate string
}

type archiveWritable interface {
	write(writer *writeBuffer) error
}

func serialize(value interface{}) ([]byte, error) {
	if value == nil {
		return []byte{}, nil
	}
	var buffer bytes.Buffer
	encoder := codec.NewEncoder(&buffer, new(codec.CborHandle))
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func min(x, y int64) int64 {
	if x < y {
		return x
	}
	return y
}

func generateHash(reader io.ReaderAt, hasherFactory func() hash.Hash) ([]byte, error) {
	hasher := hasherFactory()
	buffer := make([]byte, 1024)

	offset := int64(0)
	for ; ; {
		bytes, err := reader.ReadAt(buffer, offset)
		if err != nil && err != io.EOF {
			return nil, err
		}

		hasher.Write(buffer[:bytes])
		offset += int64(bytes)

		if err == io.EOF {
			break
		}
	}

	return hasher.Sum(nil), nil
}
