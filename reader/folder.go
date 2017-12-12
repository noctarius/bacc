package reader

import "github.com/relations-one/bacc"

type folderEntry struct {
	name       string
	timestamp  uint64
	headerSize uint32
	entryCount uint32
	metadata   map[string]interface{}
	entries    []bacc.ArchiveEntry
}

func (fe *folderEntry) HeaderSize() uint32 {
	return fe.headerSize
}

func (fe *folderEntry) EntryType() bacc.EntryType {
	return bacc.ENTRY_TYPE_FOLDER
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

func (fe *folderEntry) Metadata() map[string]interface{} {
	return fe.metadata
}

func (fe *folderEntry) Entries() []bacc.ArchiveEntry {
	return fe.entries
}
