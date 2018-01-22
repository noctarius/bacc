package bacc

import (
	"os"
	"fmt"
	"io"
	"sync/atomic"
	"crypto/rsa"
)

type archiveFileWriter struct {
	addressingMode         AddressingMode
	name                   string
	timestamp              uint64
	headerSize             uint32
	file                   *os.File
	compressedSize         uint64
	uncompressedSize       uint64
	contentOffset          uint64
	compressionMethod      CompressionMethod
	encryptionMethod       EncryptionMethod
	key                    []byte
	keyFingerprint         []byte
	signatureMethod        SignatureMethod
	certificateFingerprint []byte
	signature              []byte // always 256 bytes
	metadataSize           uint32
	metadata               []byte
	offset                 int64
	checksum               []byte // always 32 bytes
}

func (afw *archiveFileWriter) write(writer *writeBuffer) error {
	writer.mark()
	if _, err := writer.writeUtf8(afw.name); err != nil {
		return err
	}
	if _, err := writer.writeUint64(afw.timestamp); err != nil {
		return err
	}
	if _, err := writer.writeUint8(uint8(ENTRY_TYPE_FILE)); err != nil {
		return err
	}
	if _, err := writer.writeUint32(afw.headerSize); err != nil {
		return err
	}
	if _, err := writer.Write(afw.checksum); err != nil {
		return err
	}
	if afw.addressingMode == ADDRESSING_64BIT {
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
	if afw.encryptionMethod != ENCMET_UNENCRYPTED {
		if _, err := writer.Write(afw.keyFingerprint); err != nil {
			return err
		}
	}
	if _, err := writer.writeUint8(uint8(afw.signatureMethod)); err != nil {
		return err
	}
	if afw.signatureMethod != SIGMET_UNSINGED {
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
	checksum               []byte // always 32 bytes
	compressedSize         uint64
	uncompressedSize       uint64
	contentOffset          uint64
	compressionMethod      CompressionMethod
	encryptionMethod       EncryptionMethod
	keyFingerprint         string
	signatureMethod        SignatureMethod
	certificateFingerprint string
	signature              []byte
	metadata               map[string]interface{}
	reader                 *readerBuffer
	keyManager             KeyManager
}

func (fe *fileEntry) NewReader() EntryReader {
	return &fileEntryReader{
		fe:     fe,
		offset: 0,
		reader: fe.reader,
	}
}

func (fe *fileEntry) Verify() (bool, error) {
	if fe.signatureMethod == SIGMET_UNSINGED {
		return true, nil
	}

	/* TODO key, err := fe.keyManager.GetKey(fe.keyFingerprint)
	if err != nil {
		return false, err
	}*/

	// TODO verifier, err := ParsePublicKey(key)
	verifier, err := LoadKeyForVerifying("test/public.pem")
	if err != nil {
		return false, err
	}

	size := int64(fe.compressedSize)
	reader := newBoundedReader(fe.reader, int64(fe.contentOffset), size)

	err = verifier.Verify(reader, size, fe.signature, func(total uint64, processed uint64, progress float32) {
	})

	if err != nil && err != rsa.ErrVerification {
		return false, err
	}
	return err == nil, nil
}

func (fe *fileEntry) Extract(writer io.Writer, progress ProgressCallback, callback CompletionCallback) (err error) {
	key := make([]byte, 0)
	if fe.encryptionMethod != ENCMET_UNENCRYPTED {
		key, err = fe.keyManager.GetKey(fe.keyFingerprint)
		if err != nil {
			return err
		}
	}

	reader, err := createInputReader(fe, key)
	if err != nil {
		return err
	}

	_, err = fe.copySourceToSink(reader, writer, int64(fe.uncompressedSize), progress, callback)
	return err
}

func (fe *fileEntry) HeaderSize() uint32 {
	return fe.headerSize
}

func (fe *fileEntry) EntryType() EntryType {
	return ENTRY_TYPE_FILE
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

func (fe *fileEntry) CompressionMethod() CompressionMethod {
	return fe.compressionMethod
}

func (fe *fileEntry) EncryptionMethod() EncryptionMethod {
	return fe.encryptionMethod
}

func (fe *fileEntry) SignatureMethod() SignatureMethod {
	return fe.signatureMethod
}

func (fe *fileEntry) Metadata() map[string]interface{} {
	return fe.metadata
}

func (fe *fileEntry) copySourceToSink(reader io.Reader, writer io.Writer, size int64,
	progress ProgressCallback, callback CompletionCallback) (int64, error) {

	sourceOffset := int64(0)
	buffer := make([]byte, 1024*1024)
	for ; sourceOffset < size; {
		length := min(int64(len(buffer)), size-sourceOffset)
		bytes, err := reader.Read(buffer[:length])
		if err != nil {
			return -1, err
		}

		if _, err := writer.Write(buffer[:bytes]); err != nil {
			return -1, err
		}
		sourceOffset += int64(bytes)

		percent := float32(sourceOffset) * 100. / float32(size)
		progress(uint64(size), uint64(sourceOffset), percent)
	}
	callback(uint64(sourceOffset), uint64(size), true, nil)

	return size, nil
}

type fileEntryReader struct {
	fe     *fileEntry
	offset int64
	reader *readerBuffer
}

func (fer *fileEntryReader) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		atomic.StoreInt64(&fer.offset, offset)
	case io.SeekCurrent:
		fer.offset += offset
	case io.SeekEnd:
		fer.offset = int64(fer.fe.compressedSize) + offset
	}
	return fer.offset, nil
}

func (fer *fileEntryReader) Read(p []byte) (n int, err error) {
	n, err = fer.reader.ReadAt(p, fer.offset+int64(fer.fe.contentOffset))
	if err != nil {
		return 0, err
	}

	fer.offset += int64(n)
	return n, nil
}

func (fer *fileEntryReader) ReadAt(p []byte, off int64) (n int, err error) {
	return fer.reader.ReadAt(p, off+int64(fer.fe.contentOffset))
}
