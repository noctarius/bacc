package writer

import (
	"encoding/hex"
	"os"
	"io"
	"compress/gzip"
	"crypto/sha256"
	"github.com/relations-one/bacc"
	"errors"
	"time"
	"strings"
	"hash"
	"fmt"
	"github.com/hsinhoyeh/gobzip"
)

type Packager struct {
	verbose        bool
	addressingMode bacc.AddressingMode
}

func NewPackager(verbose bool) *Packager {
	return &Packager{verbose, bacc.ADDRESSING_64BIT}
}

func (p *Packager) WriteArchive(archivePath string, archiveDefinition *Entry, force64bit bool) error {
	if !force64bit {
		val, err := p.is64bitNecessary(archiveDefinition)
		if err != nil {
			return err
		}
		p.addressingMode = val
	}

	header, err := createHeader(p.addressingMode, nil)
	if err != nil {
		return err
	}

	directory, offset, err := p.buildArchiveEntryHeader(archiveDefinition, int64(header.headerSize))
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

	signArchive(archivePath, "test/private.pem")

	return nil
}

func (p *Packager) buildArchiveEntryHeader(entry *Entry, offset int64) (archiveWritable, int64, error) {
	switch entry.entryType {
	case bacc.ENTRY_TYPE_FOLDER:
		return p.createFolder(entry, offset)

	case bacc.ENTRY_TYPE_FILE:
		return p.createFile(entry, offset)

	default:
		return nil, -1, errors.New("illegal entry type found")
	}
}

func (p *Packager) createFolder(entry *Entry, offset int64) (*archiveFolderWriter, int64, error) {
	timestamp := uint64(time.Now().UnixNano())

	if entry.path != nil {
		stat, err := entry.path.Stat()
		if err != nil {
			return nil, -1, err
		}
		timestamp = uint64(stat.ModTime().UnixNano())
	}

	headerSize := bacc.BaseBytesizeFolderHeader + uint32(len([]byte(entry.name))) + 1

	metadataSize := uint32(0)
	var metadataBytes []byte
	if entry.metadata != nil {
		metadataSize = uint32(len(entry.metadata))
		bytes, err := serialize(entry.metadata)
		if err != nil {
			return nil, -1, err
		}
		metadataBytes = bytes
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

func (p *Packager) createFile(entry *Entry, offset int64) (*archiveFileWriter, int64, error) {
	stat, err := entry.path.Stat()
	if err != nil {
		return nil, -1, err
	}
	timestamp := uint64(stat.ModTime().UnixNano())

	var headerSize uint32
	if p.addressingMode == bacc.ADDRESSING_64BIT {
		headerSize = bacc.BaseBytesizeFile64Header
	} else {
		headerSize = bacc.BaseBytesizeFile32Header
	}
	headerSize += uint32(len([]byte(entry.name))) + 1

	metadataSize := uint32(0)
	var metadataBytes []byte
	if entry.metadata != nil {
		metadataSize = uint32(len(entry.metadata))
		bytes, err := serialize(entry.metadata)
		if err != nil {
			return nil, -1, err
		}
		metadataBytes = bytes
		headerSize += uint32(len(metadataBytes))
	}

	if entry.encryptionConfig.encryptionMethod != bacc.ENCMET_UNENCRYPTED {
		headerSize += 32
	}

	if entry.signatureConfig.signatureMethod != bacc.SIGMET_UNSINGED {
		headerSize += 32 + 256
	}

	uncompressedSize := uint64(stat.Size())

	reader := strings.NewReader(entry.encryptionConfig.encryptionKey)
	keyHash, err := generateHash(reader, func() hash.Hash { return sha256.New() })
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
		encryptionMethod:  entry.encryptionConfig.encryptionMethod,
		key:               []byte(entry.encryptionConfig.encryptionKey),
		keyFingerprint:    keyHash,
		metadataSize:      metadataSize,
		metadata:          metadataBytes,
		offset:            offset,
	}, offset + int64(headerSize), nil
}

func (p *Packager) is64bitNecessary(entry *Entry) (bacc.AddressingMode, error) {
	switch entry.entryType {
	case bacc.ENTRY_TYPE_FOLDER:
		if entry.entries != nil {
			for _, child := range entry.entries {
				addressingMode, err := p.is64bitNecessary(child)
				if err != nil {
					return 0, err
				}
				if addressingMode == bacc.ADDRESSING_64BIT {
					return addressingMode, nil
				}
			}
		}

	case bacc.ENTRY_TYPE_FILE:
		stat, err := entry.path.Stat()
		if err != nil {
			return 0, err
		}
		if stat.Size() > 4294967295 {
			return bacc.ADDRESSING_64BIT, nil
		}

	default:
		return 0, errors.New("illegal entry type found")
	}

	return bacc.ADDRESSING_32BIT, nil
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
	if source.compressionMethod == bacc.COMPMET_UNCOMPRESSED &&
		source.encryptionMethod == bacc.ENCMET_UNENCRYPTED {

		return copyFileContent(writer, source)
	}

	return compressAndEncryptFileContent(writer, source, source.key)
}

func compressAndEncryptFileContent(writer *writeBuffer, source *archiveFileWriter, key []byte) (int64, error) {
	s := source.file
	rb := make([]byte, 1024 * 1024)

	var w io.Writer
	switch source.encryptionMethod {
	case bacc.ENCMET_AES256:
		wt, err := newAesWriter(writer, key)
		if err != nil {
			return -1, err
		}
		w = wt
	case bacc.ENCMET_TWOFISH256:
		wt, err := newTwofishWriter(writer, key)
		if err != nil {
			return -1, err
		}
		w = wt
	case bacc.ENCMET_RSA_PRIVATE:
		// Unimplemented yet
	case bacc.ENCMET_RSA_PUBLIC:
		// Unimplemented yet
	default:
		w = writer
	}

	switch source.compressionMethod {
	case bacc.COMPMET_GZIP:
		wt, err := gzip.NewWriterLevel(w, gzip.BestCompression)
		if err != nil {
			return -1, err
		}
		w = wt
	case bacc.COMPMET_BZIP2:
		wt, err := gobzip.NewBzipWriter(w)
		if err != nil {
			return -1, err
		}
		w = wt
	}

	stat, err := s.Stat()
	if err != nil {
		return -1, err
	}

	so := int64(0)
	size := stat.Size()
	writer.mark()

	for ; so < size; {
		length := min(int64(len(rb)), size-so)
		bytes, err := s.ReadAt(rb[:length], so)
		if err != nil {
			return -1, err
		}

		if _, err := w.Write(rb[:bytes]); err != nil {
			return -1, err
		}
		so += int64(bytes)
		fmt.Print(".")
	}

	if c, success := w.(io.Closer); success {
		c.Close()
	}

	fmt.Println(" 100%")
	written := writer.writtenSinceMarker()
	return written, nil
}

func copyFileContent(writer *writeBuffer, source *archiveFileWriter) (int64, error) {
	buffer := make([]byte, 1024 * 1024)
	s := source.file
	stat, err := s.Stat()
	if err != nil {
		return -1, err
	}

	so := int64(0)
	size := stat.Size()

	for ; so < size; {
		length := min(int64(len(buffer)), size-so)
		bytes, err := s.ReadAt(buffer[:length], so)
		if err != nil {
			return -1, err
		}

		writer.Write(buffer[:bytes])
		so += int64(bytes)
		fmt.Print(".")

	}
	fmt.Println(" 100%")
	return int64(size), s.Close()
}

func checksumArchive(archivePath string, checksumOffset int64) error {
	fmt.Print("Calculating checksum: ")
	file, err := os.OpenFile(archivePath, os.O_RDWR, os.ModePerm)
	if err != nil {
		return err
	}

	hasher := sha256.New()
	buffer := make([]byte, 1024 * 1024)

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
	fmt.Println(" 100%")
	fmt.Println("Checksum: " + hex.EncodeToString(checksum))

	if _, err := file.WriteAt(checksum, checksumOffset); err != nil {
		return err
	}
	return file.Close()
}

func signArchive(archivePath string, keyPath string) error {
	fmt.Print("Signing archive: ")
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}

	signer, err := bacc.LoadKeyForSigning(keyPath)
	if err != nil {
		return err
	}

	signature, err := signer.Sign(file)
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
