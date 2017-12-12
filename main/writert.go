package main

import (
	"fmt"
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
	archiveDefinition, err := parser.ReadJsonDescriptor("./test/archive.json")
	if err != nil {
		panic(err)
	}

	packager := writer.NewPackager(true)
	if err := packager.WriteArchive("archive.bacc", archiveDefinition, false); err != nil {
		panic(err)
	}

	reader := &reader2.Reader{}
	archive, err := reader.ReadArchive("archive.bacc")
	if err != nil {
		panic(err)
	}

	if success, err := archive.Verify(false); err != nil {
		panic(err)
	} else {
		fmt.Println("")
		fmt.Print("Verification successful: ", success, "\n")

		if success {
			fmt.Println("")
			fmt.Println("Lookup Dictionary:")
			archive.ListLookupDirectory()
		}
	}
}
