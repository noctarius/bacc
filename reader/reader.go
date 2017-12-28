package reader

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

	archive := &archive{
		reader:      reader,
		header:      header,
		archivePath: archivePath,
		rootEntry:   rootEntry.(bacc.ArchiveFolder),
	}

	return archive, nil
}

func (r *Reader) readHeader(reader *reader) (*archiveHeader, error) {
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

func (r *Reader) readMetadata(reader *reader, offset int64) (map[string]interface{}, error) {
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

func (r *Reader) readEntry(reader *reader, offset int64) (bacc.ArchiveEntry, error) {
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

func (r *Reader) readFolder(reader *reader, offset int64, name string,
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

func (r *Reader) readFile(reader *reader, offset int64, name string,
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

func (r *Reader) createReader(file string) (*reader, error) {
	if f, err := os.Open(file); err != nil {
		return nil, err
	} else {
		return newReader(f)
	}
}

type reader struct {
	file        *os.File
	chunkOffset int64
	chunkLength int16
	chunk       []byte
}

func newReader(file *os.File) (*reader, error) {
	r := &reader{

		file:  file,
		chunk: make([]byte, 1024),
	}
	if err := r.readChunk(0); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *reader) readBuffer(buffer []byte, offset int64) error {
	length := len(buffer)
	r.validateChunkOffset(offset, int64(length))
	buf, err := r.slice(offset, int64(len(buffer)))
	if err != nil {
		return err
	}
	copy(buffer, buf)
	return nil
}

func (r *reader) readUint8(offset int64) (uint8, error) {
	r.validateChunkOffset(offset, 1)
	return uint8(r.chunk[offset-r.chunkOffset]), nil
}

func (r *reader) readUint16(offset int64) (uint16, error) {
	buf, err := r.slice(offset, 4)
	if err != nil {
		return 0, err
	}
	return uint16(buf[1]) | uint16(buf[0])<<8, nil
}

func (r *reader) readUint24(offset int64) (uint32, error) {
	buf, err := r.slice(offset, 3)
	if err != nil {
		return 0, err
	}
	return uint32(buf[2]) | uint32(buf[1])<<8 | uint32(buf[0])<<16, nil
}

func (r *reader) readUint32(offset int64) (uint32, error) {
	buf, err := r.slice(offset, 4)
	if err != nil {
		return 0, err
	}
	return uint32(buf[3]) | uint32(buf[2])<<8 | uint32(buf[1])<<16 | uint32(buf[0])<<24, nil
}

func (r *reader) readUint64(offset int64) (uint64, error) {
	buf, err := r.slice(offset, 8)
	if err != nil {
		return 0, err
	}
	return uint64(buf[7]) | uint64(buf[6])<<8 | uint64(buf[5])<<16 | uint64(buf[4])<<24 |
		uint64(buf[3])<<32 | uint64(buf[2])<<40 | uint64(buf[1])<<48 | uint64(buf[0])<<56, nil
}

func (r *reader) readChunk(offset int64) error {
	r.chunkOffset = offset
	if length, err := r.file.ReadAt(r.chunk, offset); err != nil {
		return err
	} else {
		r.chunkLength = int16(length)
	}
	return nil
}

func (r *reader) validateChunkOffset(offset int64, length int64) error {
	if r.chunkOffset >= offset && r.chunkOffset <= offset+length {
		return nil
	}
	return r.readChunk(offset)
}

func (r *reader) slice(offset, length int64) ([]byte, error) {
	buffer := make([]byte, length)

	soffset, remaining := offset, length
	toffset := int64(0)
	for remaining > 0 {
		rlength := min(remaining, int64(len(r.chunk)))

		if err := r.validateChunkOffset(soffset, rlength); err != nil {
			return nil, err
		}

		start := soffset - r.chunkOffset
		end := start + rlength

		copy(buffer[toffset:toffset+rlength], r.chunk[start:end])

		soffset += rlength
		toffset += rlength
		remaining -= rlength
	}
	return buffer, nil
}
