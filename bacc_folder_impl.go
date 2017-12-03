package bacc

type folderEntry struct {
	name       string
	timestamp  uint64
	headerSize uint32
	entryCount uint32
	metadata   []byte
	entries    []ArchiveEntry
}

func (fe *folderEntry) HeaderSize() uint32 {
	return fe.headerSize
}

func (fe *folderEntry) EntryType() EntryType {
	return ENTRY_TYPE_FOLDER
}

func (fe *folderEntry) Name() string {
	return fe.name
}

func (fe *folderEntry) Timestamp() uint64 {
	return fe.timestamp
}

func (fe *folderEntry) EntryCount() uint32 {
	return fe.entryCount
}

func (fe *folderEntry) Metadata() []byte {
	return fe.metadata
}

func (fe *folderEntry) Entries() []ArchiveEntry {
	return fe.entries
}
