package reader

import "github.com/relations-one/bacc"

type archiveHeader struct {
	magicHeader            uint16
	version                uint8
	bitflag                uint8
	checksum               [32]byte
	headerSize             uint32
	signatureOffset        uint64
	signatureMethod        bacc.SignatureMethod
	certificateFingerprint string
	metadata               map[string]interface{}
}

func (header *archiveHeader) MagicHeader() uint16 {
	return header.magicHeader
}

func (header *archiveHeader) Version() uint8 {
	return header.version
}

func (header *archiveHeader) Bitflag() uint8 {
	return header.bitflag
}

func (header *archiveHeader) Checksum() [32]byte {
	return header.checksum
}

func (header *archiveHeader) HeaderSize() uint32 {
	return header.headerSize
}

func (header *archiveHeader) SignatureOffset() uint64 {
	return header.signatureOffset
}

func (header *archiveHeader) SignatureMethod() bacc.SignatureMethod {
	return header.signatureMethod
}

func (header *archiveHeader) CertificateFingerprint() string {
	return header.certificateFingerprint
}

func (header *archiveHeader) Metadata() map[string]interface{} {
	return header.metadata
}

func (header *archiveHeader) Verify(allowUnsigned bool) (bool, error) {
	// TODO implement verification
	return true, nil
}

func (header *archiveHeader) AddressingMode() bacc.AddressingMode {
	return bacc.AddressingMode((header.bitflag >> 7) & 1)
}
