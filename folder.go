package bacc

import (
	"os"
	"github.com/relations-one/bacc"
	"errors"
	"fmt"
)

type archiveFolderWriter struct {
	name         string
	timestamp    uint64
	file         *os.File
	headerSize   uint32
	entryCount   uint32
	metadataSize uint32
	metadata     []byte
	entries      []archiveWritable
	offset       int64
}

func (afw *archiveFolderWriter) addChild(child archiveWritable) error {
	switch c := child.(type) {
	case *archiveFolderWriter:
		afw.entryCount++
		afw.entries = append(afw.entries, c)
	case *archiveFileWriter:
		afw.entryCount++
		afw.entries = append(afw.entries, c)
	default:
		return errors.New("illegal child type being added")
	}
	return nil
}

func (afw *archiveFolderWriter) write(writer *writeBuffer) error {
	writer.mark()
	if _, err := writer.writeUtf8(afw.name); err != nil {
		return err
	}
	if _, err := writer.writeUint64(afw.timestamp); err != nil {
		return err
	}
	if _, err := writer.writeUint8(uint8(bacc.ENTRY_TYPE_FOLDER)); err != nil {
		return err
	}
	if _, err := writer.writeUint32(afw.headerSize); err != nil {
		return err
	}
	if _, err := writer.writeUint32(afw.entryCount); err != nil {
		return err
	}
	if _, err := writer.writeUint24(afw.metadataSize); err != nil {
		return err
	}
	if afw.metadataSize > 0 {
		if _, err := writer.Write(afw.metadata); err != nil {
			return err
		}
	}
	if int64(afw.headerSize) != writer.writtenSinceMarker() {
		panic(fmt.Sprintf("Wrong header size on folder? [%d, %d]", afw.headerSize, writer.writtenSinceMarker()))
	}
	return nil
}

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
