package reader

import (
	"github.com/ugorji/go/codec"
	"reflect"
	"bytes"
	"errors"
	"os"
	"crypto/sha256"
	"github.com/relations-one/bacc"
	"crypto/rsa"
	"fmt"
	"strings"
)

type archive struct {
	header      *bacc.ArchiveHeader
	rootEntry   bacc.ArchiveFolder
	reader      *reader
	archivePath string
}

func (a *archive) Header() *bacc.ArchiveHeader {
	return a.header
}

func (a *archive) RootEntry() bacc.ArchiveFolder {
	return a.rootEntry
}

func (a *archive) ListLookupDirectory() {
	a.printEntry(a.rootEntry, 0, false)
}

func (a *archive) Verify(allowUnsigned bool) (bool, error) {
	success, err := a.checkFingerprint()
	if err != nil {
		return false, err
	}
	if !success {
		return success, nil
	}

	if a.header.SignatureMethod == bacc.SIGMET_UNSINGED && !allowUnsigned {
		return false, errors.New("unsigned archives are not allowed")
	}

	return a.checkSignature()
}

func (a *archive) printEntry(entry bacc.ArchiveEntry, indentation int, lastItem bool) {
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
			a.printEntry(child, indentation+1, uint32(i) == e.EntryCount()-1)
		}
	}
}

func (a *archive) checkSignature() (bool, error) {
	key, err := bacc.LoadKeyForVerifying("test/public.pem")
	if err != nil {
		return false, err
	}

	file, err := os.Open(a.archivePath)
	if err != nil {
		return false, err
	}

	signatureOffset := int64(a.header.SignatureOffset)
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

func (a *archive) checkFingerprint() (bool, error) {
	file, err := os.Open(a.archivePath)
	if err != nil {
		return false, err
	}

	signatureOffset := int64(a.header.SignatureOffset)

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
	return bytes.Equal(checksum, a.header.Checksum[:]), nil
}

func deserialize(data []byte) (map[string]interface{}, error) {
	reader := bytes.NewReader(data)
	decoder := codec.NewDecoder(reader, new(codec.CborHandle))
	var value map[interface{}]interface{}
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return mapping(value)
}

func mapping(deserialized map[interface{}]interface{}) (map[string]interface{}, error) {
	fixed := make(map[string]interface{}, 0)
	for k, v := range deserialized {
		var key string
		switch reflect.ValueOf(k).Kind() {
		case reflect.String:
			key = k.(string)
		default:
			return nil, errors.New("illegal metadata key, type not string")
		}

		var value interface{}
		switch reflect.ValueOf(v).Kind() {
		case reflect.Map:
			temp, err := mapping(v.(map[interface{}]interface{}))
			if err != nil {
				return nil, err
			}
			value = temp
		default:
			value = v
		}
		fixed[key] = value
	}
	return fixed, nil
}

func min(x, y int64) int64 {
	if x < y {
		return x
	}
	return y
}

func calculateBytesize(entry bacc.ArchiveEntry) int64 {
	if entry.EntryType() == bacc.ENTRY_TYPE_FILE {
		return int64(entry.HeaderSize())
	}

	folder := entry.(bacc.ArchiveFolder)

	headerSize := int64(entry.HeaderSize())
	for _, child := range folder.Entries() {
		headerSize += calculateBytesize(child)
	}
	return headerSize
}
