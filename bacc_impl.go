package bacc

import (
	"os"
	"github.com/go-errors/errors"
)

const magicHeader uint16 = 0xBACC

func (header *ArchiveHeader) AddressingMode() AddressingMode {
	return AddressingMode((header.Bitflag >> 7) & 1)
}

type archiveReaderImpl struct {
}

func newArchiveReader() ArchiveReader {
	return &archiveReaderImpl{
	}
}

func (ari *archiveReaderImpl) ReadArchive(file string) (*Archive, error) {
	reader, err := createReader(file)
	if err != nil {
		return nil, err
	}

	header, err := ari.readHeader(reader)
	if err != nil {
		return nil, err
	}

	rootEntry, err := ari.readEntry(reader, int64(header.HeaderSize), header.AddressingMode())

	archive := &Archive{
		reader:    reader,
		Header:    header,
		RootEntry: rootEntry.(ArchiveFolder),
	}

	return archive, nil
}

func (ari *archiveReaderImpl) readHeader(reader *reader) (*ArchiveHeader, error) {
	header := &ArchiveHeader{}

	magic, err := reader.readUint16(0)
	if err != nil {
		return nil, err
	}
	if magic != magicHeader {
		return nil, errors.New("Illegal archive file, magic header doesn't match")
	}

	version, err := reader.readUint8(2)
	if err != nil {
		return nil, err
	}
	if version != 0x01 {
		return nil, errors.New("Illegal archive file, unknown file format version")
	}

	header.MagicHeader = magic
	header.Version = version

	bitflag, err := reader.readUint8(3)
	if err != nil {
		return nil, err
	}

	header.Bitflag = bitflag

	reader.readBuffer(header.Checksum[:], 4)

	headerSize, err := reader.readUint32(36)
	if err != nil {
		return nil, err
	}

	header.HeaderSize = headerSize

	signatureOffset, err := reader.readUint64(40)
	if err != nil {
		return nil, err
	}

	header.SignatureOffset = signatureOffset

	signatureMethod, err := reader.readUint8(48)
	if err != nil {
		return nil, err
	}

	header.SignatureMethod = SignatureMethod(signatureMethod)

	metadataSize, err := reader.readUint24(49)
	if err != nil {
		return nil, err
	}

	header.Metadata = make([]byte, metadataSize)
	if metadataSize > 0 {
		reader.readBuffer(header.Metadata, 52)
	}

	return header, nil
}

func (ari *archiveReaderImpl) readEntry(reader *reader, offset int64, mode AddressingMode) (ArchiveEntry, error) {
	buf := make([]byte, 0)

	roffset := offset
	for {
		b, err := reader.readUint8(roffset)
		if err != nil {
			return nil, err
		}

		// Terminate byte found
		if b == 0x0 {
			break
		}

		buf = append(buf, byte(b))
		roffset++
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
		return ari.readFolder(reader, roffset, mode, name, timestamp, headerSize)
	default:
		if mode == ADDRESSING_32BIT {
			return ari.readFile32(reader, roffset, mode, name, timestamp, headerSize)
		} else {
			return ari.readFile64(reader, roffset, mode, name, timestamp, headerSize)
		}
	}
}

func (ari *archiveReaderImpl) readFolder(reader *reader, offset int64, mode AddressingMode,
	name string, timestamp uint64, headerSize uint32) (*folderEntry, error) {

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
		entries:    make([]ArchiveEntry, entryCount),
	}

	metadataSize, err := reader.readUint24(offset)
	if err != nil {
		return nil, err
	}
	offset += 4

	entry.metadata = make([]byte, metadataSize)
	if metadataSize > 0 {
		reader.readBuffer(entry.metadata, offset)
	}
	offset += int64(metadataSize) + 4

	for i := uint32(0); i < entryCount; i++ {
		child, err := ari.readEntry(reader, offset, mode)
		if err != nil {
			return nil, err
		}

		entry.entries[i] = child
		offset += calculateBytesize(child)
	}

	return entry, nil
}

func (ari *archiveReaderImpl) readFile32(reader *reader, offset int64, mode AddressingMode,
	name string, timestamp uint64, headerSize uint32) (*fileEntry32, error) {

	compressedSize, err := reader.readUint32(offset)
	if err != nil {
		return nil, err
	}
	offset += 4

	uncompressedSize, err := reader.readUint32(offset)
	if err != nil {
		return nil, err
	}
	offset += 4

	contentOffset, err := reader.readUint32(offset)
	if err != nil {
		return nil, err
	}
	offset += 4

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

	signatureMethod, err := reader.readUint8(offset)
	if err != nil {
		return nil, err
	}
	offset++

	entry := &fileEntry32{
		name:              name,
		timestamp:         timestamp,
		headerSize:        headerSize,
		compressedSize:    compressedSize,
		uncompressedSize:  uncompressedSize,
		contentOffset:     contentOffset,
		compressionMethod: CompressionMethod(compressionMethod),
		encryptionMethod:  EncryptionMethod(encryptionMethod),
		signatureMethod:   SignatureMethod(signatureMethod),
	}

	metadataSize, err := reader.readUint24(offset)
	if err != nil {
		return nil, err
	}
	offset += 4

	entry.metadata = make([]byte, metadataSize)
	if metadataSize > 0 {
		reader.readBuffer(entry.metadata, offset)
	}

	return entry, nil
}

func (ari *archiveReaderImpl) readFile64(reader *reader, offset int64, mode AddressingMode,
	name string, timestamp uint64, headerSize uint32) (*fileEntry64, error) {

	compressedSize, err := reader.readUint64(offset)
	if err != nil {
		return nil, err
	}
	offset += 8

	uncompressedSize, err := reader.readUint64(offset)
	if err != nil {
		return nil, err
	}
	offset += 8

	contentOffset, err := reader.readUint64(offset)
	if err != nil {
		return nil, err
	}
	offset += 8

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

	signatureMethod, err := reader.readUint8(offset)
	if err != nil {
		return nil, err
	}
	offset++

	entry := &fileEntry64{
		name:              name,
		timestamp:         timestamp,
		headerSize:        headerSize,
		compressedSize:    compressedSize,
		uncompressedSize:  uncompressedSize,
		contentOffset:     contentOffset,
		compressionMethod: CompressionMethod(compressionMethod),
		encryptionMethod:  EncryptionMethod(encryptionMethod),
		signatureMethod:   SignatureMethod(signatureMethod),
	}

	metadataSize, err := reader.readUint24(offset)
	if err != nil {
		return nil, err
	}
	offset += 4

	entry.metadata = make([]byte, metadataSize)
	if metadataSize > 0 {
		reader.readBuffer(entry.metadata, offset)
	}

	return entry, nil
}

func createReader(file string) (*reader, error) {
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
	return uint16(buf[0]) | uint16(buf[1])<<8, nil
}

func (r *reader) readUint24(offset int64) (uint32, error) {
	buf, err := r.slice(offset, 3)
	if err != nil {
		return 0, err
	}
	return uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16, nil
}

func (r *reader) readUint32(offset int64) (uint32, error) {
	buf, err := r.slice(offset, 4)
	if err != nil {
		return 0, err
	}
	return uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24, nil
}

func (r *reader) readUint64(offset int64) (uint64, error) {
	buf, err := r.slice(offset, 8)
	if err != nil {
		return 0, err
	}
	return uint64(buf[0]) | uint64(buf[1])<<8 | uint64(buf[2])<<16 | uint64(buf[3])<<24 |
		uint64(buf[4])<<32 | uint64(buf[5])<<40 | uint64(buf[6])<<48 | uint64(buf[7])<<56, nil
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

func max(x, y int64) int64 {
	if x > y {
		return x
	}
	return y
}

func min(x, y int64) int64 {
	if x < y {
		return x
	}
	return y
}

func calculateBytesize(entry ArchiveEntry) int64 {
	if entry.EntryType() == ENTRY_TYPE_FILE {
		return int64(entry.HeaderSize())
	}

	folder := entry.(ArchiveFolder)

	headerSize := int64(entry.HeaderSize())
	for _, child := range folder.Entries() {
		headerSize += calculateBytesize(child)
	}
	return headerSize
}
