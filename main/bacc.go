package main

import (
	"flag"
	"github.com/relationsone/bacc"
	"os"
	"fmt"
)

func main() {
	descriptor := flag.String("descriptor", "", "Defines the archive JSON descriptor file")
	out := flag.String("out", "", "Defines the output target archive")
	force64bit := flag.Bool("large", false, "Forces a 64bit archive even though all files fit into 32bit")
	verbose := flag.Bool("verbose", false, "Prints additional information")
	flag.Parse()

	if *descriptor == "" {
		fmt.Println("The archive descriptor file cannot be empty")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *out == "" {
		fmt.Println("The archive output file cannot be empty")
		flag.PrintDefaults()
		os.Exit(1)
	}

	parser := bacc.NewJsonParser(*verbose)
	jsonDescriptor, err := parser.ReadJsonDescriptor(*descriptor)
	if err != nil {
		panic(err)
	}

	packager := bacc.NewPackager(nil, *verbose)
	err = packager.WriteArchive(*out, jsonDescriptor, *force64bit)
	if err != nil {
		panic(err)
	}
}
