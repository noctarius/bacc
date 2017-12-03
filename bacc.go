package bacc

type AsyncCallback func(result bool, err error)

type ProgressCallback func(uncompressedSize uint64, extracted uint64, progress float32)

type AddressingMode uint8

const (
	ADDRESSING_32BIT AddressingMode = 0x0
	ADDRESSING_64BIT AddressingMode = 0x1
)

type SignatureMethod uint8

const (
	SIGMET_UNSINGED    SignatureMethod = 0x00
	SIGMET_RSA_PRIVATE SignatureMethod = 0x01
	SIGMET_RSA_PUBLIC  SignatureMethod = 0x02
)

type CompressionMethod uint8

const (
	COMPMET_UNCOMPRESSED CompressionMethod = 0x00
	COMPMET_GZIP         CompressionMethod = 0x01
	COMPMET_BZIP2        CompressionMethod = 0x02
)

type EncryptionMethod uint8

const (
	ENCMET_UNENCRYPTED EncryptionMethod = 0x00
	ENCMET_AES256      EncryptionMethod = 0x01
	ENCMET_TWOFISH256  EncryptionMethod = 0x02
	ENCMET_RSA_PRIVATE EncryptionMethod = 0x03
	ENCMET_RSA_PUBLIC  EncryptionMethod = 0x04
)

type EntryType uint8

const (
	ENTRY_TYPE_FOLDER EntryType = 0x00
	ENTRY_TYPE_FILE   EntryType = 0x01
)

type ArchiveHeader struct {
	MagicHeader     uint16
	Version         uint8
	Bitflag         uint8
	Checksum        [32]byte
	HeaderSize      uint32
	SignatureOffset uint64
	SignatureMethod SignatureMethod
	Metadata        []byte
}

type ArchiveEntry interface {
	Name() string
	Timestamp() uint64
	HeaderSize() uint32
	Metadata() []byte
	EntryType() EntryType
}

type ArchiveFolder interface {
	Name() string
	Timestamp() uint64
	EntryCount() uint32
	Metadata() []byte
	Entries() []ArchiveEntry
}

type ArchiveFile interface {
	Name() string
	Timestamp() uint64
	CompressedSize() uint64
	UncompressedSize() uint64
	ContentOffset() uint64
	CompressionMethod() CompressionMethod
	EncryptionMethod() EncryptionMethod
	SignatureMethod() SignatureMethod
	Metadata() []byte
	Verify(callback AsyncCallback)
	Extract(progress ProgressCallback, callback AsyncCallback)
}

type Archive struct {
	Header    *ArchiveHeader
	RootEntry ArchiveFolder
	reader    *reader
}

type ArchiveReader interface {
	ReadArchive(file string) (*Archive, error)
}
