package main

import (
	"fmt"
	"github.com/relationsone/bacc"
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

	keyManager := &keyManagerImpl{}

	parser := bacc.NewJsonParser(true)
	archiveDefinition, err := parser.ReadJsonDescriptor("./test/archive.json")
	if err != nil {
		panic(err)
	}

	packager := bacc.NewPackager(keyManager, true)
	if err := packager.WriteArchive("archive.bacc", archiveDefinition, false); err != nil {
		panic(err)
	}

	reader := bacc.NewReader(keyManager)
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

type keyManagerImpl struct {
}

func (km *keyManagerImpl) GetKey(fingerprint string) ([]byte, error) {
	switch fingerprint {
	case "e932d7e1-bcf5-4aab-bd39-7f02c89394d7":
		return []byte("206bca26b1158ab1dfc7416e8016ad15"), nil

	case "d4d951d7-fcd6-4936-b0a5-3e1f9c983167":
		return []byte("7708398af3d5726a3918120f62a589e89770f96a6fb83eff0612aa531c8395b8"), nil
	}
	panic("Unknown fingerprint in keymanager")
}
