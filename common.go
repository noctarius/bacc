package bacc

import (
	"github.com/ugorji/go/codec"
	"bytes"
	"io"
	"reflect"
	"github.com/go-errors/errors"
)

type encryptionConfig struct {
	encryptionMethod      EncryptionMethod
	encryptionKey         string
	encryptionCertificate string
}

type signatureConfig struct {
	signatureMethod      SignatureMethod
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

func deserialize(data []byte) (map[string]interface{}, error) {
	reader := bytes.NewReader(data)
	decoder := codec.NewDecoder(reader, new(codec.CborHandle))
	var value map[interface{}]interface{}
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return mapping(value)
}

func mapping(deserialized map[interface{}]interface{}) (map[string]interface{}, error) {
	fixed := make(map[string]interface{}, 0)
	for k, v := range deserialized {
		var key string
		switch reflect.ValueOf(k).Kind() {
		case reflect.String:
			key = k.(string)
		default:
			return nil, errors.New("illegal metadata key, type not string")
		}

		var value interface{}
		switch reflect.ValueOf(v).Kind() {
		case reflect.Map:
			temp, err := mapping(v.(map[interface{}]interface{}))
			if err != nil {
				return nil, err
			}
			value = temp
		default:
			value = v
		}
		fixed[key] = value
	}
	return fixed, nil
}

func calculateBytesize(entry ArchiveEntry) int64 {
	if entry.EntryType() == ENTRY_TYPE_FILE {
		return int64(entry.HeaderSize())
	}

	folder := entry.(ArchiveFolder)

	headerSize := int64(entry.HeaderSize())
	for _, child := range folder.Entries() {
		headerSize += calculateBytesize(child)
	}
	return headerSize
}

type relativeReaderAt struct {
	reader     io.ReaderAt
	baseOffset int64
}

func (rra *relativeReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	return rra.reader.ReadAt(p, off+rra.baseOffset)
}
