package writer

import (
	"os"
	"github.com/relations-one/bacc"
	"fmt"
)

type archiveFileWriter struct {
	addressingMode         bacc.AddressingMode
	name                   string
	timestamp              uint64
	headerSize             uint32
	file                   *os.File
	compressedSize         uint64
	uncompressedSize       uint64
	contentOffset          uint64
	compressionMethod      bacc.CompressionMethod
	encryptionMethod       bacc.EncryptionMethod
	key                    []byte
	keyFingerprint         []byte
	signatureMethod        bacc.SignatureMethod
	certificateFingerprint []byte
	signature              []byte // always 256 bytes
	metadataSize           uint32
	metadata               []byte
	offset                 int64
}

func (afw *archiveFileWriter) write(writer *writeBuffer) error {
	writer.mark()
	if _, err := writer.writeUtf8(afw.name); err != nil {
		return err
	}
	if _, err := writer.writeUint64(afw.timestamp); err != nil {
		return err
	}
	if _, err := writer.writeUint8(uint8(bacc.ENTRY_TYPE_FILE)); err != nil {
		return err
	}
	if _, err := writer.writeUint32(afw.headerSize); err != nil {
		return err
	}
	if afw.addressingMode == bacc.ADDRESSING_64BIT {
		if _, err := writer.writeUint64(afw.compressedSize); err != nil {
			return err
		}
		if _, err := writer.writeUint64(afw.uncompressedSize); err != nil {
			return err
		}
		if _, err := writer.writeUint64(afw.contentOffset); err != nil {
			return err
		}
	} else {
		if _, err := writer.writeUint32(uint32(afw.compressedSize)); err != nil {
			return err
		}
		if _, err := writer.writeUint32(uint32(afw.uncompressedSize)); err != nil {
			return err
		}
		if _, err := writer.writeUint32(uint32(afw.contentOffset)); err != nil {
			return err
		}
	}
	if _, err := writer.writeUint8(uint8(afw.compressionMethod)); err != nil {
		return err
	}
	if _, err := writer.writeUint8(uint8(afw.encryptionMethod)); err != nil {
		return err
	}
	if afw.encryptionMethod != bacc.ENCMET_UNENCRYPTED {
		if _, err := writer.Write(afw.keyFingerprint); err != nil {
			return err
		}
	}
	if _, err := writer.writeUint8(uint8(afw.signatureMethod)); err != nil {
		return err
	}
	if afw.signatureMethod != bacc.SIGMET_UNSINGED {
		if _, err := writer.Write(afw.certificateFingerprint); err != nil {
			return err
		}
		writer.skip(256)
	}
	if _, err := writer.writeUint24(afw.metadataSize); err != nil {
		return err
	}
	if afw.metadataSize > 0 {
		if _, err := writer.Write(afw.metadata); err != nil {
			return err
		}
	}
	if int64(afw.headerSize) != writer.writtenSinceMarker() {
		panic(fmt.Sprintf("Wrong header size on file %s? [%d, %d]",
			afw.name, afw.headerSize, writer.writtenSinceMarker()))
	}
	return nil
}
