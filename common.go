package bacc

import (
	"github.com/ugorji/go/codec"
	"bytes"
	"io"
	"reflect"
	"github.com/go-errors/errors"
	"hash"
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

func createOutputWriter(writer *writeBuffer, source *archiveFileWriter, key []byte) (io.Writer, error) {
	w, err := newEncryptor(writer, source, key)
	if err != nil {
		return nil, errors.New(err)
	}

	return newCompressor(w, source)
}

func createInputReader(source *fileEntry, key []byte) (io.Reader, error) {
	reader := source.NewReader()
	r, err := newDecompressor(reader, source)
	if err != nil {
		return nil, err
	}

	return newDecryptor(r, source, key)
}

func generateSigningHash(reader io.Reader, total int64, progress ProgressCallback, hasherFactory func() hash.Hash) ([]byte, error) {
	hasher := hasherFactory()
	buffer := make([]byte, 1024*1024)

	offset := int64(0)
	for ; ; {
		bytes, err := reader.Read(buffer)
		if err != nil && err != io.EOF {
			return nil, err
		}

		hasher.Write(buffer[:bytes])
		offset += int64(bytes)

		percent := float32(float64(offset) * 100. / float64(total))
		progress(uint64(total), uint64(offset), percent)

		if err == io.EOF {
			break
		}
	}

	return hasher.Sum(nil), nil
}

type boundedReader struct {
	reader     io.ReaderAt
	baseOffset int64
	size       int64
	offset     int64
}

func newBoundedReader(reader io.ReaderAt, offset int64, size int64) io.Reader {
	return &boundedReader{
		reader:     reader,
		baseOffset: offset,
		size:       size,
		offset:     0,
	}
}

func (r *boundedReader) Read(p []byte) (n int, err error) {
	l := int64(len(p))

	remaining := r.size - r.offset
	read := min(l, remaining)
	v := make([]byte, read)

	n, err = r.reader.ReadAt(v, r.offset+r.baseOffset)
	if err != nil && err != io.EOF {
		return 0, err
	}

	r.offset += int64(n)

	if r.offset == r.size {
		err = io.EOF
	}

	return n, err
}
