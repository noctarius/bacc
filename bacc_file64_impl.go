package bacc

type fileEntry64 struct {
	name              string
	timestamp         uint64
	headerSize        uint32
	compressedSize    uint64
	uncompressedSize  uint64
	contentOffset     uint64
	compressionMethod CompressionMethod
	encryptionMethod  EncryptionMethod
	signatureMethod   SignatureMethod
	metadata          []byte
}

func (fe *fileEntry64) Verify(callback AsyncCallback) {
	panic("implement me")
}

func (fe *fileEntry64) Extract(progress ProgressCallback, callback AsyncCallback) {
	panic("implement me")
}

func (fe *fileEntry64) HeaderSize() uint32 {
	return fe.headerSize
}

func (fe *fileEntry64) EntryType() EntryType {
	return ENTRY_TYPE_FILE
}

func (fe *fileEntry64) Name() string {
	return fe.name
}

func (fe *fileEntry64) Timestamp() uint64 {
	return fe.timestamp
}

func (fe *fileEntry64) CompressedSize() uint64 {
	return fe.compressedSize
}

func (fe *fileEntry64) UncompressedSize() uint64 {
	return fe.uncompressedSize
}

func (fe *fileEntry64) ContentOffset() uint64 {
	return fe.contentOffset
}

func (fe *fileEntry64) CompressionMethod() CompressionMethod {
	return fe.compressionMethod
}

func (fe *fileEntry64) EncryptionMethod() EncryptionMethod {
	return fe.encryptionMethod
}

func (fe *fileEntry64) SignatureMethod() SignatureMethod {
	return fe.signatureMethod
}

func (fe *fileEntry64) Metadata() []byte {
	return fe.metadata
}
