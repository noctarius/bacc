package bacc

import (
	"github.com/relations-one/bacc"
	"crypto/rsa"
	"os"
	"crypto/sha256"
	"fmt"
	"strings"
	"bytes"
	"github.com/go-errors/errors"
)

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

	var metadataData []byte = nil
	if metadata != nil && len(metadata) > 0 {
		md, err := serialize(metadata)
		if err != nil {
			return nil, err
		}
		metadataData = md
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

type archiveHeader struct {
	magicHeader            uint16
	version                uint8
	bitflag                uint8
	checksum               [32]byte
	headerSize             uint32
	signatureOffset        uint64
	signatureMethod        bacc.SignatureMethod
	certificateFingerprint string
	metadata               map[string]interface{}
}

func (header *archiveHeader) MagicHeader() uint16 {
	return header.magicHeader
}

func (header *archiveHeader) Version() uint8 {
	return header.version
}

func (header *archiveHeader) Bitflag() uint8 {
	return header.bitflag
}

func (header *archiveHeader) Checksum() [32]byte {
	return header.checksum
}

func (header *archiveHeader) HeaderSize() uint32 {
	return header.headerSize
}

func (header *archiveHeader) SignatureOffset() uint64 {
	return header.signatureOffset
}

func (header *archiveHeader) SignatureMethod() bacc.SignatureMethod {
	return header.signatureMethod
}

func (header *archiveHeader) CertificateFingerprint() string {
	return header.certificateFingerprint
}

func (header *archiveHeader) Metadata() map[string]interface{} {
	return header.metadata
}

func (header *archiveHeader) Verify(allowUnsigned bool) (bool, error) {
	// TODO implement verification
	return true, nil
}

func (header *archiveHeader) AddressingMode() bacc.AddressingMode {
	return bacc.AddressingMode((header.bitflag >> 7) & 1)
}

type readerArchive struct {
	header      bacc.ArchiveHeader
	rootEntry   bacc.ArchiveFolder
	reader      *readerBuffer
	archivePath string
}

func (a *readerArchive) Header() bacc.ArchiveHeader {
	return a.header
}

func (a *readerArchive) RootEntry() bacc.ArchiveFolder {
	return a.rootEntry
}

func (a *readerArchive) ListLookupDirectory() {
	a.printEntry(a.rootEntry, 0, false)
}

func (a *readerArchive) Verify(allowUnsigned bool) (bool, error) {
	success, err := a.checkFingerprint()
	if err != nil {
		return false, err
	}
	if !success {
		return success, nil
	}

	if a.header.SignatureMethod() == bacc.SIGMET_UNSINGED && !allowUnsigned {
		return false, errors.New("unsigned archives are not allowed")
	}

	return a.checkSignature()
}

func (a *readerArchive) printEntry(entry bacc.ArchiveEntry, indentation int, lastItem bool) {
	for i := 0; i < indentation; i++ {
		fmt.Print("│ ")
	}
	switch e := entry.(type) {
	case bacc.ArchiveFolder:
		fmt.Println("├ " + entry.Name())

	case bacc.ArchiveFile:
		var compressionRatio = float64(100)
		if e.UncompressedSize() > 0 {
			compressionRatio = float64(e.CompressedSize()) * 100.0 / float64(e.UncompressedSize())
		}
		if !lastItem {
			fmt.Print("├ ")
		} else {
			fmt.Print("└ ")
		}
		fmt.Println(fmt.Sprintf("%s [%s, %s, %d] %.2f %%, metadata: %s",
			strings.Replace(e.Name(), "\r", "", -1), e.CompressionMethod().String(),
			e.EncryptionMethod().String(), e.ContentOffset(), compressionRatio, e.Metadata()))
	}

	switch e := entry.(type) {
	case bacc.ArchiveFolder:
		for i, child := range e.Entries() {
			a.printEntry(child, indentation+1, uint32(i) == e.EntryCount()-1)
		}
	}
}

func (a *readerArchive) checkSignature() (bool, error) {
	key, err := bacc.LoadKeyForVerifying("test/public.pem")
	if err != nil {
		return false, err
	}

	file, err := os.Open(a.archivePath)
	if err != nil {
		return false, err
	}

	signatureOffset := int64(a.header.SignatureOffset())
	signature := make([]byte, 256)
	_, err = file.ReadAt(signature, signatureOffset)
	if err != nil {
		return false, err
	}

	err = key.Verify(file, signatureOffset, signature)
	if err != nil && err != rsa.ErrVerification {
		return false, err
	}
	return err == nil, nil
}

func (a *readerArchive) checkFingerprint() (bool, error) {
	file, err := os.Open(a.archivePath)
	if err != nil {
		return false, err
	}

	signatureOffset := int64(a.header.SignatureOffset())

	hasher := sha256.New()
	buffer := make([]byte, 1024)

	stat, err := file.Stat()
	if err != nil {
		return false, err
	}

	firstBlock := true
	size := stat.Size()
	offset := int64(0)
	for ; offset < size; {
		length := min(int64(len(buffer)), size-offset)
		bytes, err := file.ReadAt(buffer[:length], offset)
		if err != nil {
			return false, err
		}

		if firstBlock {
			firstBlock = false
			override := make([]byte, 32)
			copy(buffer[4:], override)
		}

		breakOut := false
		if offset+int64(bytes) >= signatureOffset {
			bytes = int(signatureOffset - offset)
			breakOut = true
		}

		hasher.Write(buffer[:bytes])
		offset += int64(bytes)

		if breakOut {
			break
		}
	}

	checksum := hasher.Sum(nil)
	expectedChecksum := a.header.Checksum()
	return bytes.Equal(checksum, expectedChecksum[:]), nil
}
