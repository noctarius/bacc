package bacc

import (
	"encoding/hex"
	"os"
	"io"
	"crypto/sha256"
	"time"
	"strings"
	"fmt"
	"github.com/go-errors/errors"
)

type Packager struct {
	keyManager     KeyManager
	verbose        bool
	addressingMode AddressingMode
}

func NewPackager(keyManager KeyManager, verbose bool) *Packager {
	return &Packager{keyManager, verbose, ADDRESSING_64BIT}
}

func (p *Packager) WriteArchive(archivePath string, archiveDefinition *JsonArchive, force64bit bool) error {
	root := archiveDefinition.root
	if !force64bit {
		val, err := p.is64bitNecessary(root)
		if err != nil {
			return err
		}
		p.addressingMode = val
	}

	header, err := createHeader(archiveDefinition, p.addressingMode, nil)
	if err != nil {
		return err
	}

	directory, offset, err := p.buildArchiveEntryHeader(root, int64(header.headerSize))
	if err != nil {
		return err
	}

	if _, err := os.Stat(archivePath); !os.IsNotExist(err) {
		if err := os.Remove(archivePath); err != nil {
			return err
		}
	}

	archiveFile, err := os.Create(archivePath)
	if err != nil {
		return err
	}

	writer := newWriteBuffer(archiveFile)
	if offset, err := p.walkFolderAndWriteContent(directory.(*archiveFolderWriter), writer, offset); err != nil {
		return err
	} else {
		// Set signature offset to last element in the archive
		header.signatureOffset = uint64(offset)
	}

	writer.offset = 0
	if err := header.write(writer); err != nil {
		return err
	}
	fmt.Print("Writing header: ")
	if err := walkFolderAndWriteHeader(directory.(*archiveFolderWriter), writer); err != nil {
		return err
	}
	fmt.Println(" 100%")
	archiveFile.Close()

	checksumArchive(archivePath, header.calculateChecksumOffset())

	signArchive(archivePath, int64(header.signatureOffset), "test/private.pem")

	return nil
}

func (p *Packager) buildArchiveEntryHeader(entry *JsonEntry, offset int64) (archiveWritable, int64, error) {
	switch entry.entryType {
	case ENTRY_TYPE_FOLDER:
		return p.createFolder(entry, offset)

	case ENTRY_TYPE_FILE:
		return p.createFile(entry, offset)

	default:
		return nil, -1, errors.New("illegal entry type found")
	}
}

func (p *Packager) createFolder(entry *JsonEntry, offset int64) (*archiveFolderWriter, int64, error) {
	timestamp := uint64(time.Now().UnixNano())

	if entry.path != nil {
		stat, err := entry.path.Stat()
		if err != nil {
			return nil, -1, err
		}
		timestamp = uint64(stat.ModTime().UnixNano())
	}

	headerSize := BaseBytesizeFolderHeader + uint32(len([]byte(entry.name))) + 1

	metadataSize := uint32(0)
	var metadataBytes []byte
	if entry.metadata != nil && len(entry.metadata) > 0 {
		bytes, err := serialize(entry.metadata)
		if err != nil {
			return nil, -1, err
		}
		metadataBytes = bytes
		metadataSize = uint32(len(metadataBytes))
		headerSize += uint32(len(metadataBytes))
	}

	folder := &archiveFolderWriter{
		name:         entry.name,
		timestamp:    timestamp,
		headerSize:   headerSize,
		file:         entry.path,
		entryCount:   uint32(len(entry.entries)),
		entries:      make([]archiveWritable, 0),
		metadataSize: metadataSize,
		metadata:     metadataBytes,
		offset:       offset,
	}
	offset += int64(headerSize)

	if entry.entries != nil {
		for _, child := range entry.entries {
			c, o, err := p.buildArchiveEntryHeader(child, offset)
			if err != nil {
				return nil, -1, err
			}
			folder.entries = append(folder.entries, c)
			offset = o
		}
	}

	return folder, offset, nil
}

func (p *Packager) createFile(entry *JsonEntry, offset int64) (*archiveFileWriter, int64, error) {
	stat, err := entry.path.Stat()
	if err != nil {
		return nil, -1, err
	}
	timestamp := uint64(stat.ModTime().UnixNano())

	var headerSize uint32
	if p.addressingMode == ADDRESSING_64BIT {
		headerSize = BaseBytesizeFile64Header
	} else {
		headerSize = BaseBytesizeFile32Header
	}
	headerSize += uint32(len([]byte(entry.name))) + 1

	metadataSize := uint32(0)
	var metadataBytes []byte
	if entry.metadata != nil && len(entry.metadata) > 0 {
		bytes, err := serialize(entry.metadata)
		if err != nil {
			return nil, -1, err
		}
		metadataBytes = bytes
		metadataSize = uint32(len(metadataBytes))
		headerSize += uint32(len(metadataBytes))
	}

	if entry.encryptionConfig.encryptionMethod != ENCMET_UNENCRYPTED {
		headerSize += 32
	}

	if entry.signatureConfig.signatureMethod != SIGMET_UNSINGED {
		headerSize += 32 + 256
	}

	uncompressedSize := uint64(stat.Size())

	fingerprint := ""
	encryptionMethod := entry.encryptionConfig.encryptionMethod
	if encryptionMethod == ENCMET_AES256 || encryptionMethod == ENCMET_TWOFISH256 {
		fingerprint = entry.encryptionConfig.encryptionKey

	} else if encryptionMethod == ENCMET_RSA_PRIVATE || encryptionMethod == ENCMET_RSA_PUBLIC {
		fingerprint = entry.encryptionConfig.encryptionCertificate
	}

	key, err := p.keyManager.GetKey(fingerprint)
	if err != nil {
		return nil, -1, errors.New(err)
	}
	keyFingerprint, err := p.serializeFingerprint(fingerprint)
	if err != nil {
		return nil, -1, err
	}

	checksum, err := checksumInputFile(entry.pathString)
	if err != nil {
		return nil, -1, err
	}

	return &archiveFileWriter{
		name:              entry.name,
		timestamp:         timestamp,
		headerSize:        headerSize,
		file:              entry.path,
		addressingMode:    p.addressingMode,
		uncompressedSize:  uncompressedSize,
		compressionMethod: entry.compressionMethod,
		encryptionMethod:  encryptionMethod,
		key:               key,
		keyFingerprint:    keyFingerprint,
		metadataSize:      metadataSize,
		metadata:          metadataBytes,
		offset:            offset,
		checksum:          checksum,
	}, offset + int64(headerSize), nil
}

func (p *Packager) serializeFingerprint(fingerprint string) ([]byte, error) {
	if strings.TrimSpace(fingerprint) == "" {
		return make([]byte, 32), nil
	}

	fingerprint = strings.Replace(fingerprint, "-", "", -1)

	lenFingerprint := len(fingerprint)
	if lenFingerprint > 32 {
		return nil, errors.New("Fingerprint cannot be longer than 32 characters")
	}

	if lenFingerprint < 32 {
		fingerprint = strings.Repeat("0", 32-lenFingerprint) + fingerprint
	}

	return []byte(fingerprint), nil
}

func (p *Packager) is64bitNecessary(entry *JsonEntry) (AddressingMode, error) {
	switch entry.entryType {
	case ENTRY_TYPE_FOLDER:
		if entry.entries != nil {
			for _, child := range entry.entries {
				addressingMode, err := p.is64bitNecessary(child)
				if err != nil {
					return 0, err
				}
				if addressingMode == ADDRESSING_64BIT {
					return addressingMode, nil
				}
			}
		}

	case ENTRY_TYPE_FILE:
		stat, err := entry.path.Stat()
		if err != nil {
			return 0, err
		}
		if stat.Size() > 4294967295 {
			return ADDRESSING_64BIT, nil
		}

	default:
		return 0, errors.New("illegal entry type found")
	}

	return ADDRESSING_32BIT, nil
}

func walkFolderAndWriteHeader(folder *archiveFolderWriter, writer *writeBuffer) error {
	if err := folder.write(writer); err != nil {
		return err
	}
	for _, child := range folder.entries {
		switch c := child.(type) {
		case *archiveFolderWriter:
			if err := walkFolderAndWriteHeader(c, writer); err != nil {
				return err
			}

		default:
			if err := c.write(writer); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *Packager) walkFolderAndWriteContent(folder *archiveFolderWriter,
	writer *writeBuffer, offset int64) (int64, error) {

	for _, child := range folder.entries {
		switch c := child.(type) {
		case *archiveFolderWriter:
			o, err := p.walkFolderAndWriteContent(c, writer, offset)
			if err != nil {
				return -1, err
			}
			offset = o

		case *archiveFileWriter:
			fmt.Print(fmt.Sprintf("Writing content for %s: ", strings.Replace(c.name, "\r", "", -1)))
			c.contentOffset = uint64(offset)
			writer.offset = offset
			o, err := p.pushFileContent(writer, c)
			if err != nil {
				return -1, err
			}
			c.compressedSize = uint64(o)
			offset = offset + o
		}
	}

	return offset, nil
}

func (p *Packager) pushFileContent(writer *writeBuffer, source *archiveFileWriter) (int64, error) {
	var progress ProgressCallback = func(total uint64, processed uint64, progress float32) {
		fmt.Print(".")
	}

	compressionMethod := source.compressionMethod
	var callback CompletionCallback = func(read uint64, processed uint64, result bool, err error) {
		if p.verbose && compressionMethod != COMPMET_UNCOMPRESSED {
			fmt.Println(fmt.Sprintf(" 100%% - Compressed from %d to %d => %.2f %%",
				read, processed, float64(processed)*100./float64(read)))
		} else {
			fmt.Println(" 100%")
		}
	}

	// Process actual file content
	return p.copyCompressAndEncryptFileContent(writer, source, progress, callback)
}

func (p *Packager) copyCompressAndEncryptFileContent(writer *writeBuffer, source *archiveFileWriter,
	progress ProgressCallback, callback CompletionCallback) (int64, error) {

	// Mark the current offset for size calculation
	writer.mark()

	// Create the output writer to just copy, compress, encrypt
	outputWriter, err := createOutputWriter(writer, source, source.key)
	if err != nil {
		return -1, err
	}

	s := source.file
	stat, err := s.Stat()
	if err != nil {
		return -1, err
	}
	size := stat.Size()

	if _, err := p.copySourceToSink(s, outputWriter, size, progress, callback); err != nil {
		return -1, nil
	}

	if c, success := outputWriter.(io.Closer); success {
		c.Close()
	}

	// How many bytes have been written
	written := writer.writtenSinceMarker()

	callback(uint64(size), uint64(written), true, nil)
	return written, nil
}

func (p *Packager) copySourceToSink(reader io.ReaderAt, writer io.Writer, size int64,
	progress ProgressCallback, callback CompletionCallback) (int64, error) {

	sourceOffset := int64(0)
	buffer := make([]byte, 1024*1024)
	for ; sourceOffset < size; {
		length := min(int64(len(buffer)), size-sourceOffset)
		bytes, err := reader.ReadAt(buffer[:length], sourceOffset)
		if err != nil {
			return -1, err
		}

		if _, err := writer.Write(buffer[:bytes]); err != nil {
			return -1, err
		}
		sourceOffset += int64(bytes)

		percent := float32(float64(sourceOffset) * 100. / float64(size))
		progress(uint64(size), uint64(sourceOffset), percent)
	}
	callback(uint64(sourceOffset), uint64(size), true, nil)

	return size, nil
}

func checksumInputFile(path string) ([]byte, error) {
	fmt.Print(fmt.Sprintf("Calculating checksum for input %s: ", path))
	file, err := os.OpenFile(path, os.O_RDWR, os.ModePerm)
	if err != nil {
		return nil, err
	}

	hasher := sha256.New()
	buffer := make([]byte, 1024*1024)

	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}

	size := stat.Size()
	offset := int64(0)
	for ; offset < size; {
		length := min(int64(len(buffer)), size-offset)
		bytes, err := file.ReadAt(buffer[:length], offset)
		if err != nil {
			return nil, err
		}

		hasher.Write(buffer[:bytes])
		offset += int64(bytes)
		fmt.Print(".")
	}

	checksum := hasher.Sum(nil)
	fmt.Println(fmt.Sprintf(" 100%% (%d)", offset))
	return checksum, nil
}

func checksumArchive(archivePath string, checksumOffset int64) error {
	fmt.Print("Calculating checksum: ")
	file, err := os.OpenFile(archivePath, os.O_RDWR, os.ModePerm)
	if err != nil {
		return err
	}

	hasher := sha256.New()
	buffer := make([]byte, 1024*1024)

	stat, err := file.Stat()
	if err != nil {
		return err
	}

	firstBlock := true
	size := stat.Size()
	offset := int64(0)
	for ; offset < size; {
		length := min(int64(len(buffer)), size-offset)
		bytes, err := file.ReadAt(buffer[:length], offset)
		if err != nil {
			return err
		}

		if firstBlock {
			firstBlock = false
			override := make([]byte, 32)
			copy(buffer[4:], override)
		}

		hasher.Write(buffer[:bytes])
		offset += int64(bytes)
		fmt.Print(".")
	}

	checksum := hasher.Sum(nil)
	fmt.Println(fmt.Sprintf(" 100%% (%d)", offset))
	fmt.Println("checksum: " + hex.EncodeToString(checksum))

	if _, err := file.WriteAt(checksum, checksumOffset); err != nil {
		return err
	}
	return file.Close()
}

func signArchive(archivePath string, signatureOffset int64, keyPath string) error {
	fmt.Print("Signing archive: ")
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}

	signer, err := LoadKeyForSigning(keyPath)
	if err != nil {
		return err
	}

	reader := newBoundedReader(file, 0, signatureOffset)
	signature, err := signer.Sign(reader, signatureOffset, func(total uint64, processed uint64, progress float32) {
		fmt.Print(".")
	})

	if err != nil {
		return err
	}

	if err := file.Close(); err != nil {
		return err
	}

	if file, err := os.OpenFile(archivePath, os.O_WRONLY|os.O_APPEND, os.ModePerm); err != nil {
		return err
	} else {
		if _, err := file.Write(signature); err != nil {
			return err
		}

		fmt.Println(" 100%")
		return file.Close()
	}
}
