package bacc

import (
	"os"
	"github.com/relations-one/bacc"
	"fmt"
	"io"
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
		if _, err := writer.Write(afw.signature); err != nil {
			return err
		}
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

func (fe *fileEntry) Verify(callback bacc.CompletionCallback) {
	panic("implement me")
}

func (fe *fileEntry) Extract(progress bacc.ProgressCallback, callback bacc.CompletionCallback) {
	//contentOffset := fe.contentOffset
	//compressedSize := fe.compressedSize

	//progress()

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