package bacc

import "io"

const MagicHeader uint16 = 0xBACC

const (
	BaseBytesizeArchiveHeader = uint32(2 + 1 + 1 + 32 + 4 + 8 + 1 + 32 + 3)
	BaseBytesizeFolderHeader  = uint32(8 + 1 + 4 + 4 + 3)
	BaseBytesizeFile32Header  = uint32(8 + 1 + 4 + 4 + 4 + 4 + 1 + 1 + 1 + 3)
	BaseBytesizeFile64Header  = uint32(8 + 1 + 4 + 8 + 8 + 8 + 1 + 1 + 1 + 3)
)

type CompletionCallback func(read uint64, processed uint64, result bool, err error)

type ProgressCallback func(total uint64, processed uint64, progress float32)

type AddressingMode uint8

func (am AddressingMode) String() string {
	switch am {
	case ADDRESSING_32BIT:
		return "32bit addressing"

	default:
		return "64bit addressing"
	}
}

const (
	ADDRESSING_32BIT AddressingMode = 0x0
	ADDRESSING_64BIT AddressingMode = 0x1
)

type SignatureMethod uint8

func (sm SignatureMethod) String() string {
	switch sm {
	case SIGMET_RSA_PRIVATE:
		return "rsa-private"

	default:
		return "unsigned"
	}
}

const (
	SIGMET_UNSINGED    SignatureMethod = 0x00
	SIGMET_RSA_PRIVATE SignatureMethod = 0x01
)

type CompressionMethod uint8

func (cm CompressionMethod) String() string {
	switch cm {
	case COMPMET_GZIP:
		return "gzip-compressed"

	case COMPMET_BZIP2:
		return "bzip2-compressed"

	default:
		return "uncompressed"
	}
}

const (
	COMPMET_UNCOMPRESSED CompressionMethod = 0x00
	COMPMET_GZIP         CompressionMethod = 0x01
	COMPMET_BZIP2        CompressionMethod = 0x02
)

type EncryptionMethod uint8

func (em EncryptionMethod) String() string {
	switch em {
	case ENCMET_AES256:
		return "AES256-encrypted"

	case ENCMET_TWOFISH256:
		return "TWOFISH256-encrypted"

	case ENCMET_RSA_PRIVATE:
		return "rsa-private-encrypted"

	case ENCMET_RSA_PUBLIC:
		return "rsa-public-encrypted"

	default:
		return "unencrypted"
	}
}

const (
	ENCMET_UNENCRYPTED EncryptionMethod = 0x00
	ENCMET_AES256      EncryptionMethod = 0x01
	ENCMET_TWOFISH256  EncryptionMethod = 0x02
	ENCMET_RSA_PRIVATE EncryptionMethod = 0x03
	ENCMET_RSA_PUBLIC  EncryptionMethod = 0x04
)

type EntryType uint8

func (et EntryType) String() string {
	switch et {
	case ENTRY_TYPE_FOLDER:
		return "folder-type"

	default:
		return "file-type"
	}
}

const (
	ENTRY_TYPE_FOLDER EntryType = 0x00
	ENTRY_TYPE_FILE   EntryType = 0x01
)

type ArchiveHeader interface {
	MagicHeader() uint16
	Version() uint8
	Bitflag() uint8
	Checksum() [32]byte
	HeaderSize() uint32
	SignatureOffset() uint64
	SignatureMethod() SignatureMethod
	CertificateFingerprint() string
	Metadata() map[string]interface{}
	AddressingMode() AddressingMode
	Verify(allowUnsigned bool) (bool, error)
	//VerifyAsync(progress ProgressCallback, callback CompletionCallback, allowUnsigned bool)
}

type ArchiveEntry interface {
	Name() string
	Timestamp() uint64
	HeaderSize() uint32
	Metadata() map[string]interface{}
	EntryType() EntryType
}

type ArchiveFolder interface {
	Name() string
	Timestamp() uint64
	HeaderSize() uint32
	Metadata() map[string]interface{}
	EntryType() EntryType
	EntryCount() uint32
	Entries() []ArchiveEntry
}

type ArchiveFile interface {
	Name() string
	Timestamp() uint64
	HeaderSize() uint32
	Metadata() map[string]interface{}
	EntryType() EntryType
	CompressedSize() uint64
	UncompressedSize() uint64
	ContentOffset() uint64
	CompressionMethod() CompressionMethod
	EncryptionMethod() EncryptionMethod
	SignatureMethod() SignatureMethod
	Verify(callback CompletionCallback)
	Extract(progress ProgressCallback, callback CompletionCallback)
	NewReader() io.Reader
}

type Archive interface {
	Header() ArchiveHeader
	RootEntry() ArchiveFolder
	ListLookupDirectory()
	Verify(allowUnsigned bool) (bool, error)
	//VerifyAsync(progress ProgressCallback, callback CompletionCallback, allowUnsigned bool)
}
