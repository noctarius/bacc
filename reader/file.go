package reader

import (
	"github.com/relations-one/bacc"
	"io"
)

type fileEntry struct {
	name                   string
	timestamp              uint64
	headerSize             uint32
	compressedSize         uint64
	uncompressedSize       uint64
	contentOffset          uint64
	compressionMethod      bacc.CompressionMethod
	encryptionMethod       bacc.EncryptionMethod
	keyFingerprint         string
	signatureMethod        bacc.SignatureMethod
	certificateFingerprint string
	metadata               map[string]interface{}
}

func (fe *fileEntry) NewReader() io.Reader {
	panic("implement me")
}

func (fe *fileEntry) Verify(callback bacc.AsyncCallback) {
	panic("implement me")
}

func (fe *fileEntry) Extract(progress bacc.ProgressCallback, callback bacc.AsyncCallback) {
	contentOffset := fe.contentOffset
	compressedSize := fe.compressedSize

	progress()

	panic("implement me")
}

func (fe *fileEntry) HeaderSize() uint32 {
	return fe.headerSize
}

func (fe *fileEntry) EntryType() bacc.EntryType {
	return bacc.ENTRY_TYPE_FILE
}

func (fe *fileEntry) Name() string {
	return fe.name
}

func (fe *fileEntry) Timestamp() uint64 {
	return fe.timestamp
}

func (fe *fileEntry) CompressedSize() uint64 {
	return fe.compressedSize
}

func (fe *fileEntry) UncompressedSize() uint64 {
	return fe.uncompressedSize
}

func (fe *fileEntry) ContentOffset() uint64 {
	return fe.contentOffset
}

func (fe *fileEntry) CompressionMethod() bacc.CompressionMethod {
	return fe.compressionMethod
}

func (fe *fileEntry) EncryptionMethod() bacc.EncryptionMethod {
	return fe.encryptionMethod
}

func (fe *fileEntry) SignatureMethod() bacc.SignatureMethod {
	return fe.signatureMethod
}

func (fe *fileEntry) Metadata() map[string]interface{} {
	return fe.metadata
}
