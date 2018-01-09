package bacc

import (
	"os"
	"github.com/go-errors/errors"
	"encoding/hex"
	"github.com/relations-one/bacc"
)

type Reader struct {
	keyManager     bacc.KeyManager
	addressingMode bacc.AddressingMode
}

func NewReader(keyManager bacc.KeyManager) *Reader {
	return &Reader{keyManager: keyManager}
}

func (r *Reader) ReadArchive(archivePath string) (bacc.Archive, error) {
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
		rootEntry:   rootEntry.(bacc.ArchiveFolder),
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
	if magic != bacc.MagicHeader {
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

	if err := reader.readBuffer(header.checksum[:], offset); err != nil {
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

	header.signatureMethod = bacc.SignatureMethod(signatureMethod)

	fingerprint := make([]byte, 32)
	if err := reader.readBuffer(fingerprint, offset); err != nil {
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
		reader.readBuffer(buffer, offset)
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

func (r *Reader) readEntry(reader *readerBuffer, offset int64) (bacc.ArchiveEntry, error) {
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

	switch bacc.EntryType(entryType) {
	case bacc.ENTRY_TYPE_FOLDER:
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
		entries:    make([]bacc.ArchiveEntry, entryCount),
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

	var compressedSize, uncompressedSize, contentOffset uint64
	if r.addressingMode == bacc.ADDRESSING_64BIT {
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
	if bacc.EncryptionMethod(encryptionMethod) != bacc.ENCMET_UNENCRYPTED {
		fingerprint := make([]byte, 32)
		if err := reader.readBuffer(fingerprint, offset); err != nil {
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
	if bacc.SignatureMethod(signatureMethod) != bacc.SIGMET_UNSINGED {
		fingerprint := make([]byte, 32)
		if err := reader.readBuffer(fingerprint, offset); err != nil {
			return nil, err
		}
		certificateFingerprint = hex.EncodeToString(fingerprint)
		offset += 32
	}

	entry := &fileEntry{
		name:                   name,
		timestamp:              timestamp,
		headerSize:             headerSize,
		compressedSize:         compressedSize,
		uncompressedSize:       uncompressedSize,
		contentOffset:          contentOffset,
		compressionMethod:      bacc.CompressionMethod(compressionMethod),
		encryptionMethod:       bacc.EncryptionMethod(encryptionMethod),
		keyFingerprint:         keyFingerprint,
		signatureMethod:        bacc.SignatureMethod(signatureMethod),
		certificateFingerprint: certificateFingerprint,
		metadata:               make(map[string]interface{}),
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
