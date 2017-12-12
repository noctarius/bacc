package writer

import "github.com/relations-one/bacc"

const (
	checksumOffset               = 0x04
	signatureOffsetOffset        = 0x28
	certificateFingerprintOffset = 0x31
)

type archiveHeaderWriter struct {
	magicHeader            uint16
	version                uint8
	bitflag                uint8
	checksum               [32]byte
	headerSize             uint32
	signatureOffset        uint64
	signatureMethod        bacc.SignatureMethod
	certificateFingerprint string
	metadataSize           uint32
	metadata               []byte
}

func createHeader(archive *Archive, addressingMode bacc.AddressingMode,
	metadata map[string]interface{}) (*archiveHeaderWriter, error) {

	metadataData, err := serialize(metadata)
	if err != nil {
		return nil, err
	}

	bitflag := uint8(0)
	if addressingMode == bacc.ADDRESSING_64BIT {
		bitflag |= 1 << 7
	}

	return &archiveHeaderWriter{
		magicHeader:            bacc.MagicHeader,
		version:                0x01,
		bitflag:                bitflag,
		signatureMethod:        archive.signatureConfig.signatureMethod,
		certificateFingerprint: archive.signatureConfig.signatureCertificate,
		metadataSize:           uint32(len(metadataData)),
		metadata:               metadataData,
		headerSize:             bacc.BaseBytesizeArchiveHeader + uint32(len(metadataData)),
	}, nil
}

func (ahw *archiveHeaderWriter) calculateChecksumOffset() int64 {
	return checksumOffset
}

func (ahw *archiveHeaderWriter) calculateSignatureOffsetOffset() int64 {
	return signatureOffsetOffset
}

func (ahw *archiveHeaderWriter) calculateCertificateFingerprintOffset() int64 {
	return certificateFingerprintOffset
}

func (ahw *archiveHeaderWriter) write(writer *writeBuffer) error {
	writer.mark()
	if _, err := writer.writeUint16(ahw.magicHeader); err != nil {
		return err
	}
	if _, err := writer.writeUint8(ahw.version); err != nil {
		return err
	}
	if _, err := writer.writeUint8(ahw.bitflag); err != nil {
		return err
	}
	writer.skip(32) // checksum will be added later in the creation process
	if _, err := writer.writeUint32(ahw.headerSize); err != nil {
		return err
	}
	if _, err := writer.writeUint64(ahw.signatureOffset); err != nil {
		return err
	}
	if _, err := writer.writeUint8(uint8(ahw.signatureMethod)); err != nil {
		return err
	}
	writer.skip(32) // signature fingerprint
	if _, err := writer.writeUint24(ahw.metadataSize); err != nil {
		return err
	}
	if ahw.metadataSize > 0 {
		if _, err := writer.Write(ahw.metadata); err != nil {
			return err
		}
	}
	if int64(ahw.headerSize) != writer.writtenSinceMarker() {
		panic("Wrong header size on header?")
	}
	return nil
}
