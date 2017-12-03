package bacc

type fileEntry32 struct {
	name              string
	timestamp         uint64
	headerSize        uint32
	compressedSize    uint32
	uncompressedSize  uint32
	contentOffset     uint32
	compressionMethod CompressionMethod
	encryptionMethod  EncryptionMethod
	signatureMethod   SignatureMethod
	metadata          []byte
}

func (fe *fileEntry32) Verify(callback AsyncCallback) {
	panic("implement me")
}

func (fe *fileEntry32) Extract(progress ProgressCallback, callback AsyncCallback) {
	panic("implement me")
}

func (fe *fileEntry32) HeaderSize() uint32 {
	return fe.headerSize
}

func (fe *fileEntry32) EntryType() EntryType {
	return ENTRY_TYPE_FILE
}

func (fe *fileEntry32) Name() string {
	return fe.name
}

func (fe *fileEntry32) Timestamp() uint64 {
	return fe.timestamp
}

func (fe *fileEntry32) CompressedSize() uint64 {
	return uint64(fe.compressedSize)
}

func (fe *fileEntry32) UncompressedSize() uint64 {
	return uint64(fe.uncompressedSize)
}

func (fe *fileEntry32) ContentOffset() uint64 {
	return uint64(fe.contentOffset)
}

func (fe *fileEntry32) CompressionMethod() CompressionMethod {
	return fe.compressionMethod
}

func (fe *fileEntry32) EncryptionMethod() EncryptionMethod {
	return fe.encryptionMethod
}

func (fe *fileEntry32) SignatureMethod() SignatureMethod {
	return fe.signatureMethod
}

func (fe *fileEntry32) Metadata() []byte {
	return fe.metadata
}
