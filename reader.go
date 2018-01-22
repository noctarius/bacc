package bacc

import (
	"os"
	"github.com/go-errors/errors"
	"encoding/hex"
)

type Reader struct {
	keyManager     KeyManager
	addressingMode AddressingMode
}

func NewReader(keyManager KeyManager) *Reader {
	return &Reader{keyManager: keyManager}
}

func (r *Reader) ReadArchive(archivePath string) (Archive, error) {
	reader, err := r.createReader(archivePath)
	if err != nil {
		return nil, err
	}

	header, err := r.readHeader(reader)
	if err != nil {
		return nil, err
	}

	r.addressingMode = header.AddressingMode()
	rootEntry, err := r.readEntry(reader, int64(header.headerSize))

	archive := &readerArchive{
		reader:      reader,
		header:      header,
		archivePath: archivePath,
		rootEntry:   rootEntry.(ArchiveFolder),
	}

	return archive, nil
}

func (r *Reader) readHeader(reader *readerBuffer) (*archiveHeader, error) {
	header := &archiveHeader{
		metadata: make(map[string]interface{}),
	}

	offset := int64(0)

	magic, err := reader.readUint16(offset)
	if err != nil {
		return nil, err
	}
	if magic != MagicHeader {
		return nil, errors.New("illegal archive file, magic header doesn't match")
	}
	offset += 2

	version, err := reader.readUint8(offset)
	if err != nil {
		return nil, err
	}
	if version != 0x01 {
		return nil, errors.New("illegal archive file, unknown file format version")
	}
	offset += 1

	header.magicHeader = magic
	header.version = version

	bitflag, err := reader.readUint8(offset)
	if err != nil {
		return nil, err
	}
	offset += 1

	header.bitflag = bitflag

	if _, err := reader.ReadAt(header.checksum[:], offset); err != nil {
		return nil, err
	}
	offset += int64(len(header.checksum))

	headerSize, err := reader.readUint32(offset)
	if err != nil {
		return nil, err
	}
	offset += 4

	header.headerSize = headerSize

	signatureOffset, err := reader.readUint64(offset)
	if err != nil {
		return nil, err
	}
	offset += 8

	header.signatureOffset = signatureOffset

	signatureMethod, err := reader.readUint8(offset)
	if err != nil {
		return nil, err
	}
	offset += 1

	header.signatureMethod = SignatureMethod(signatureMethod)

	fingerprint := make([]byte, 32)
	if _, err := reader.ReadAt(fingerprint, offset); err != nil {
		return nil, err
	}
	header.certificateFingerprint = hex.EncodeToString(fingerprint)
	offset += 32

	if table, err := r.readMetadata(reader, offset); err != nil {
		return nil, err
	} else {
		header.metadata = table
	}

	return header, nil
}

func (r *Reader) readMetadata(reader *readerBuffer, offset int64) (map[string]interface{}, error) {
	metadataSize, err := reader.readUint24(offset)
	if err != nil {
		return nil, err
	}
	offset += 3

	var table map[string]interface{}
	if metadataSize > 0 {
		buffer := make([]byte, metadataSize)
		_, err = reader.ReadAt(buffer, offset)
		if err != nil {
			return nil, err
		}

		t, err := deserialize(buffer)
		if err != nil {
			return nil, err
		}
		table = t
	} else {
		table = make(map[string]interface{}, 0)
	}
	return table, nil
}

func (r *Reader) readEntry(reader *readerBuffer, offset int64) (ArchiveEntry, error) {
	buf := make([]byte, 0)

	roffset := offset
	for {
		b, err := reader.readUint8(roffset)
		if err != nil {
			return nil, err
		}
		roffset++

		// Terminate byte found
		if b == 0x0 {
			break
		}

		buf = append(buf, byte(b))
	}

	name := string(buf)

	timestamp, err := reader.readUint64(roffset)
	if err != nil {
		return nil, err
	}
	roffset += 8

	entryType, err := reader.readUint8(roffset)
	if err != nil {
		return nil, err
	}
	roffset++

	headerSize, err := reader.readUint32(roffset)
	if err != nil {
		return nil, err
	}
	roffset += 4

	switch EntryType(entryType) {
	case ENTRY_TYPE_FOLDER:
		return r.readFolder(reader, roffset, name, timestamp, headerSize)
	default:
		return r.readFile(reader, roffset, name, timestamp, headerSize)
	}
}

func (r *Reader) readFolder(reader *readerBuffer, offset int64, name string,
	timestamp uint64, headerSize uint32) (*folderEntry, error) {

	entryCount, err := reader.readUint32(offset)
	if err != nil {
		return nil, err
	}
	offset += 4

	entry := &folderEntry{
		name:       name,
		timestamp:  timestamp,
		headerSize: headerSize,
		entryCount: entryCount,
		metadata:   make(map[string]interface{}),
		entries:    make([]ArchiveEntry, entryCount),
	}

	metadataSize, err := reader.readUint24(offset)
	if err != nil {
		return nil, err
	}

	if table, err := r.readMetadata(reader, offset); err != nil {
		return nil, err
	} else {
		entry.metadata = table
	}
	offset += int64(metadataSize) + 3

	for i := uint32(0); i < entryCount; i++ {
		child, err := r.readEntry(reader, offset)
		if err != nil {
			return nil, err
		}

		entry.entries[i] = child
		offset += calculateBytesize(child)
	}

	return entry, nil
}

func (r *Reader) readFile(reader *readerBuffer, offset int64, name string,
	timestamp uint64, headerSize uint32) (*fileEntry, error) {

	checksum := make([]byte, 32)
	n, err := reader.ReadAt(checksum, offset)
	if err != nil {
		return nil, err
	}
	offset += int64(n)

	var compressedSize, uncompressedSize, contentOffset uint64
	if r.addressingMode == ADDRESSING_64BIT {
		cs, err := reader.readUint64(offset)
		if err != nil {
			return nil, err
		}
		offset += 8
		compressedSize = cs

		us, err := reader.readUint64(offset)
		if err != nil {
			return nil, err
		}
		offset += 8
		uncompressedSize = us

		co, err := reader.readUint64(offset)
		if err != nil {
			return nil, err
		}
		offset += 8
		contentOffset = co

	} else {
		cs, err := reader.readUint32(offset)
		if err != nil {
			return nil, err
		}
		offset += 4
		compressedSize = uint64(cs)

		us, err := reader.readUint32(offset)
		if err != nil {
			return nil, err
		}
		offset += 4
		uncompressedSize = uint64(us)

		co, err := reader.readUint32(offset)
		if err != nil {
			return nil, err
		}
		offset += 4
		contentOffset = uint64(co)
	}

	compressionMethod, err := reader.readUint8(offset)
	if err != nil {
		return nil, err
	}
	offset++

	encryptionMethod, err := reader.readUint8(offset)
	if err != nil {
		return nil, err
	}
	offset++

	keyFingerprint := ""
	if EncryptionMethod(encryptionMethod) != ENCMET_UNENCRYPTED {
		fingerprint := make([]byte, 32)
		if _, err := reader.ReadAt(fingerprint, offset); err != nil {
			return nil, err
		}
		keyFingerprint = hex.EncodeToString(fingerprint)
		offset += 32
	}

	signatureMethod, err := reader.readUint8(offset)
	if err != nil {
		return nil, err
	}
	offset++

	certificateFingerprint := ""
	signature := make([]byte, 0)
	if SignatureMethod(signatureMethod) != SIGMET_UNSINGED {
		fingerprint := make([]byte, 32)
		if _, err := reader.ReadAt(fingerprint, offset); err != nil {
			return nil, err
		}
		certificateFingerprint = hex.EncodeToString(fingerprint)
		offset += 32

		signature = make([]byte, 256)
		if _, err := reader.ReadAt(signature, offset); err != nil {
			return nil, err
		}
		offset += 256
	}

	entry := &fileEntry{
		name:                   name,
		timestamp:              timestamp,
		headerSize:             headerSize,
		checksum:               checksum,
		compressedSize:         compressedSize,
		uncompressedSize:       uncompressedSize,
		contentOffset:          contentOffset,
		compressionMethod:      CompressionMethod(compressionMethod),
		encryptionMethod:       EncryptionMethod(encryptionMethod),
		keyFingerprint:         keyFingerprint,
		signatureMethod:        SignatureMethod(signatureMethod),
		certificateFingerprint: certificateFingerprint,
		signature:              signature,
		metadata:               make(map[string]interface{}),
		reader:                 reader,
		keyManager:             r.keyManager,
	}

	metadataSize, err := reader.readUint24(offset)
	if err != nil {
		return nil, err
	}

	if table, err := r.readMetadata(reader, offset); err != nil {
		return nil, err
	} else {
		entry.metadata = table
	}
	offset += int64(metadataSize) + 3

	return entry, nil
}

func (r *Reader) createReader(file string) (*readerBuffer, error) {
	if f, err := os.Open(file); err != nil {
		return nil, err
	} else {
		return newReader(f)
	}
}
