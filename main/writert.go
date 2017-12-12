package main

import (
	"github.com/relations-one/bacc"
	"fmt"
	"strings"
	reader2 "github.com/relations-one/bacc/reader"
	"github.com/relations-one/bacc/writer"
)

func main() {
	/*if err := bacc.WriteArchive("archive.bacc"); err != nil {
		panic(err)
	}

	archive, err := bacc.ReadArchive("archive.bacc")
	if err != nil {
		panic(err)
	}

	if success, err := archive.Verify(); err != nil {
		panic(err)
	} else {
		print("Verification successful: ", success, "\n")
	}*/

	parser := writer.NewJsonParser(true)
	rootEntry, err := parser.ReadJsonDescriptor("./test/archive.json")
	if err != nil {
		panic(err)
	}

	packager := writer.NewPackager(true)
	if err := packager.WriteArchive("archive.bacc", rootEntry, false); err != nil {
		panic(err)
	}

	reader := &reader2.Reader{}
	archive, err := reader.ReadArchive("archive.bacc")
	if err != nil {
		panic(err)
	}

	if success, err := archive.Verify(); err != nil {
		panic(err)
	} else {
		fmt.Print("Verification successful: ", success, "\n")

		if success {
			printEntry(archive.RootEntry(), 0, false)
		}
	}
}

func printEntry(entry bacc.ArchiveEntry, indentation int, lastItem bool) {
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
		fmt.Println(fmt.Sprintf("%s [%s, %s, %d] %.2f %%", strings.Replace(e.Name(), "\r", "", -1),
			e.CompressionMethod().String(), e.EncryptionMethod().String(), e.ContentOffset(), compressionRatio))
	}

	switch e := entry.(type) {
	case bacc.ArchiveFolder:
		for i, child := range e.Entries() {
			printEntry(child, indentation+1, uint32(i) == e.EntryCount()-1)
		}
	}
}
