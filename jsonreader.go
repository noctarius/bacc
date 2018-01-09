package bacc

import (
	"os"
	"encoding/json"
	"io/ioutil"
	"github.com/relations-one/bacc"
	"path/filepath"
	"github.com/go-errors/errors"
	"github.com/zealic/xignore"
	"fmt"
)

type JsonParser struct {
	verbose bool
}

type Archive struct {
	signatureConfig *signatureConfig
	root            *Entry
}

type Entry struct {
	name              string
	entryType         bacc.EntryType
	pathString        string
	path              *os.File
	compressionMethod bacc.CompressionMethod
	encryptionConfig  *encryptionConfig
	signatureConfig   *signatureConfig
	entries           []*Entry
	ignoreMatcher     *xignore.IgnoreMatcher
	metadata          map[string]interface{}
	parent            *Entry
}

func NewJsonParser(verbose bool) *JsonParser {
	return &JsonParser{verbose}
}

func (e *Entry) String() string {
	return fmt.Sprintf("entry {name: %s, entryType: %s, path: %s, compressionMethod: %s, "+
		"encryptionConfig: %s, signatureConfig: %s, metadata: %s, entries: %s}", e.name, e.entryType, e.pathString,
		e.compressionMethod.String(), e.encryptionConfig, e.signatureConfig, e.metadata, e.entries)
}

func (e *Entry) fullPath() string {
	path := e.name
	parent := e.parent
	for ; parent != nil; {
		path = filepath.Join(parent.name, path)
		parent = parent.parent
	}
	return path
}

func (jp *JsonParser) ReadJsonDescriptor(jsonDescriptor string) (*Archive, error) {
	descriptor, err := jp.unmarshallJsonDescriptor(jsonDescriptor)
	if err != nil {
		return nil, err
	}

	archive, err := jp.beginParseJsonDescriptor(descriptor)
	if err != nil {
		return nil, err
	}

	return archive, nil
}

func (jp *JsonParser) unmarshallJsonDescriptor(jsonDescriptor string) (map[string]interface{}, error) {
	f, err := os.Open(jsonDescriptor)
	if err != nil {
		return nil, err
	}

	j, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	var data interface{}
	err = json.Unmarshal(j, &data)
	if err != nil {
		return nil, err
	}

	return data.(map[string]interface{}), nil
}

func (jp *JsonParser) beginParseJsonDescriptor(descriptor map[string]interface{}) (*Archive, error) {
	encryptionConfig := &encryptionConfig{
		encryptionMethod: bacc.ENCMET_UNENCRYPTED,
	}
	signatureConfig := &signatureConfig{
		signatureMethod: bacc.SIGMET_UNSINGED,
	}

	archive := &Archive{
		signatureConfig: signatureConfig,
	}

	if jp.existsKey("signatureMethod", descriptor) {
		archive.signatureConfig = jp.readSignatureConfig(descriptor)
	}

	rootDescriptor := descriptor["root"]
	if rootDescriptor == nil {
		return nil, errors.New("missing root element in the archive descriptor")
	}

	root, err := jp.parseJsonDescriptor(rootDescriptor.(map[string]interface{}),
		bacc.COMPMET_UNCOMPRESSED, encryptionConfig, signatureConfig, nil)

	if err != nil {
		return nil, err
	}

	root.name = "root:/"
	archive.root = root
	return archive, nil
}

func (jp *JsonParser) parseJsonDescriptor(descriptor map[string]interface{}, compressionMethod bacc.CompressionMethod,
	encryptionConfig *encryptionConfig, signatureConfig *signatureConfig, parent *Entry) (*Entry, error) {

	t := descriptor["type"]
	switch t {
	case "FILE":
		return jp.parseFile(descriptor, compressionMethod, encryptionConfig, signatureConfig, parent)

	case "FOLDER":
		return jp.parseFolder(descriptor, compressionMethod, encryptionConfig, signatureConfig, parent)

	default:
		return nil, errors.New("unknown element type found")
	}
}

func (jp *JsonParser) parseFolder(descriptor map[string]interface{}, compressionMethod bacc.CompressionMethod,
	encryptionConfig *encryptionConfig, signatureConfig *signatureConfig, parent *Entry) (*Entry, error) {

	entry := &Entry{
		name:              jp.readString("name", "", descriptor),
		entryType:         bacc.ENTRY_TYPE_FOLDER,
		entries:           make([]*Entry, 0),
		compressionMethod: compressionMethod,
		encryptionConfig:  encryptionConfig,
		signatureConfig:   signatureConfig,
		parent:            parent,
	}

	path := jp.readString("path", "", descriptor)
	var folder *os.File
	if path != "" {
		path, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		folder = f
		s, err := folder.Stat()
		if err != nil {
			return nil, err
		}
		if !s.IsDir() {
			return nil, errors.New(path + " is not a folder")
		}
		entry.path = folder
		entry.pathString = path
	}

	if jp.existsKey("compressionMethod", descriptor) {
		entry.compressionMethod = jp.readCompressionMethod(descriptor)
	}
	if jp.existsKey("encryptionMethod", descriptor) {
		entry.encryptionConfig = jp.readEncryptionConfig(descriptor)
	}
	if jp.existsKey("signatureMethod", descriptor) {
		entry.signatureConfig = jp.readSignatureConfig(descriptor)
	}

	excludes := descriptor["excludes"]
	if excludes != nil {
		excludeDefs := excludes.([]interface{})
		patterns := make([]string, len(excludeDefs))
		for i := range excludeDefs {
			patterns[i] = excludeDefs[i].(string)
		}
		entry.ignoreMatcher = xignore.New(patterns)
	}

	md := descriptor["metadata"]
	if md != nil {
		entry.metadata = md.(map[string]interface{})
	}

	transitive := jp.readBoolean("transitive", false, descriptor)
	if transitive && folder != nil {
		err := jp.scanFolder(entry, folder, entry.compressionMethod,
			entry.encryptionConfig, entry.signatureConfig, entry)

		if err != nil {
			return nil, err
		}
	}

	entries := descriptor["entries"]
	if e, success := entries.([]interface{}); success {
		for _, i := range e {
			childDescriptor := i.(map[string]interface{})
			child, err := jp.parseJsonDescriptor(childDescriptor, entry.compressionMethod,
				entry.encryptionConfig, entry.signatureConfig, entry)

			if err != nil {
				return nil, err
			}

			if child != nil {
				found := false
				for i, e := range entry.entries {
					if e.name == child.name {
						found = true
						entry.entries[i] = child
					}
				}

				if !found {
					entry.entries = append(entry.entries, child)
				}
			}
		}
	}

	if jp.verbose && entry.fullPath() != "" {
		fmt.Println(fmt.Sprintf("Adding %s [FOLDER, explicitly defined]", entry.fullPath()))
	}

	return entry, nil
}
func (jp *JsonParser) scanFolder(entry *Entry, folder *os.File, compressionMethod bacc.CompressionMethod,
	encryptionConfig *encryptionConfig, signatureConfig *signatureConfig, parent *Entry) (error) {

	names, err := entry.path.Readdirnames(-1)
	if err != nil {
		return err
	}

	for _, name := range names {
		path := filepath.Join(folder.Name(), name)

		if jp.isIgnored(path, entry) {
			continue
		}

		child, err := os.Open(path)
		if err != nil {
			return err
		}

		stat, err := child.Stat()
		if err != nil {
			return err
		}

		if stat.IsDir() {
			folder, err := jp.createScannedFolder(child, compressionMethod, encryptionConfig, signatureConfig, parent)
			if err != nil {
				return err
			}
			err = jp.scanFolder(folder, child, compressionMethod, encryptionConfig, signatureConfig, folder)
			if err != nil {
				return err
			}
			entry.entries = append(entry.entries, folder)

		} else {
			file, err := jp.createScannedFile(child, compressionMethod, encryptionConfig, signatureConfig, parent)
			if err != nil {
				return err
			}
			entry.entries = append(entry.entries, file)
		}
	}
	return nil
}

func (jp *JsonParser) isIgnored(path string, entry *Entry) bool {
	parent := entry
	var ignoreMatcher *xignore.IgnoreMatcher = nil
	for {
		if ignoreMatcher != nil || parent == nil {
			break
		}
		ignoreMatcher = parent.ignoreMatcher
		parent = parent.parent
	}
	if ignoreMatcher == nil {
		return false
	}

	matches, err := ignoreMatcher.Matches(path)
	if err != nil {
		panic(err)
	}
	return matches
}

func (jp *JsonParser) createScannedFolder(folder *os.File, compressionMethod bacc.CompressionMethod,
	encryptionConfig *encryptionConfig, signatureConfig *signatureConfig, parent *Entry) (*Entry, error) {

	path, err := filepath.Abs(filepath.Dir(folder.Name()))
	if err != nil {
		return nil, err
	}

	entry := &Entry{
		name:              filepath.Base(folder.Name()),
		entryType:         bacc.ENTRY_TYPE_FOLDER,
		entries:           make([]*Entry, 0),
		path:              folder,
		pathString:        path,
		compressionMethod: compressionMethod,
		encryptionConfig:  encryptionConfig,
		signatureConfig:   signatureConfig,
		metadata:          nil,
		parent:            parent,
	}

	if jp.verbose && entry.fullPath() != "" {
		fmt.Println(fmt.Sprintf("Adding %s [FOLDER, added by directory scan]", entry.fullPath()))
	}

	return entry, nil
}

func (jp *JsonParser) createScannedFile(file *os.File, compressionMethod bacc.CompressionMethod,
	encryptionConfig *encryptionConfig, signatureConfig *signatureConfig, parent *Entry) (*Entry, error) {

	path, err := filepath.Abs(file.Name())
	if err != nil {
		return nil, err
	}

	entry := &Entry{
		name:              filepath.Base(file.Name()),
		entryType:         bacc.ENTRY_TYPE_FILE,
		path:              file,
		pathString:        path,
		compressionMethod: compressionMethod,
		encryptionConfig:  encryptionConfig,
		signatureConfig:   signatureConfig,
		metadata:          nil,
		parent:            parent,
	}

	if jp.verbose && entry.fullPath() != ""{
		fmt.Println(fmt.Sprintf("Adding %s [FILE, added by directory scan]", entry.fullPath()))
	}

	return entry, nil
}

func (jp *JsonParser) parseFile(descriptor map[string]interface{}, compressionMethod bacc.CompressionMethod,
	encryptionConfig *encryptionConfig, signatureConfig *signatureConfig, parent *Entry) (*Entry, error) {

	entry := &Entry{
		name:              jp.readString("name", "", descriptor),
		entryType:         bacc.ENTRY_TYPE_FILE,
		compressionMethod: compressionMethod,
		encryptionConfig:  encryptionConfig,
		signatureConfig:   signatureConfig,
		parent:            parent,
	}

	path := jp.readString("path", "", descriptor)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	s, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if s.IsDir() {
		return nil, errors.New(path + " is not a file")
	}
	entry.path = file
	entry.pathString = path

	if jp.existsKey("compressionMethod", descriptor) {
		entry.compressionMethod = jp.readCompressionMethod(descriptor)
	}
	if jp.existsKey("encryptionMethod", descriptor) {
		entry.encryptionConfig = jp.readEncryptionConfig(descriptor)
	}
	if jp.existsKey("signatureMethod", descriptor) {
		entry.signatureConfig = jp.readSignatureConfig(descriptor)
	}

	entry.metadata = jp.parseMetadata(descriptor)

	if jp.verbose && entry.fullPath() != "" {
		fmt.Println(fmt.Sprintf("Adding %s [FILE, explicitly defined]", entry.fullPath()))
	}

	return entry, nil
}

func (jp *JsonParser) parseMetadata(descriptor map[string]interface{}) (map[string]interface{}) {
	md := descriptor["metadata"]
	if md == nil {
		return nil
	}

	conv := md.([]interface{})

	metadata := make(map[string]interface{})
	for _, i := range conv {
		entry := i.(map[string]interface{})
		for k, v := range entry {
			metadata[k] = v
		}
	}

	return metadata
}

func (jp *JsonParser) existsKey(attribute string, descriptor map[string]interface{}) bool {
	return descriptor[attribute] != nil
}

func (jp *JsonParser) readString(attribute string, defaultValue string, descriptor map[string]interface{}) string {
	attr := descriptor[attribute]
	if attr != nil {
		return attr.(string)
	}
	return defaultValue
}

func (jp *JsonParser) readBoolean(attribute string, defaultValue bool, descriptor map[string]interface{}) bool {
	attr := descriptor[attribute]
	if attr != nil {
		return attr.(bool)
	}
	return defaultValue
}

func (jp *JsonParser) readCompressionMethod(descriptor map[string]interface{}) bacc.CompressionMethod {
	compressionMethod := jp.readString("compressionMethod", "UNCOMPRESSED", descriptor)
	switch compressionMethod {
	case "UNCOMPRESSED":
		return bacc.COMPMET_UNCOMPRESSED

	case "GZIP":
		return bacc.COMPMET_GZIP

	case "BZIP2":
		return bacc.COMPMET_BZIP2

	default:
		panic(errors.New("illegal compression method selected"))
	}
}

func (jp *JsonParser) readEncryptionConfig(descriptor map[string]interface{}) *encryptionConfig {
	encryptionMethod := jp.readString("encryptionMethod", "UNENCRYPTED", descriptor)
	encryptionKey := jp.readString("encryptionKey", "", descriptor)
	encryptionCertificate := jp.readString("encryptionCertificate", "", descriptor)

	config := &encryptionConfig{}
	switch encryptionMethod {
	case "UNENCRYPTED":
		config.encryptionMethod = bacc.ENCMET_UNENCRYPTED

	case "AES256":
		config.encryptionMethod = bacc.ENCMET_AES256
		config.encryptionKey = encryptionKey

	case "TWOFISH256":
		config.encryptionMethod = bacc.ENCMET_TWOFISH256
		config.encryptionKey = encryptionKey

	case "RSA-PRIVATE":
		config.encryptionMethod = bacc.ENCMET_RSA_PRIVATE
		config.encryptionCertificate = encryptionCertificate

	case "RSA-PUBLIC":
		config.encryptionMethod = bacc.ENCMET_RSA_PRIVATE
		config.encryptionCertificate = encryptionCertificate

	default:
		panic(errors.New("illegal encryption method selected"))
	}

	if (config.encryptionMethod == bacc.ENCMET_AES256 ||
		config.encryptionMethod == bacc.ENCMET_TWOFISH256) && config.encryptionKey == "" {

		panic(errors.New("missing key on encryption configuration"))
	}

	if (config.encryptionMethod == bacc.ENCMET_RSA_PRIVATE ||
		config.encryptionMethod == bacc.ENCMET_RSA_PUBLIC) && config.encryptionCertificate == "" {

		panic(errors.New("missing key on encryption configuration"))
	}

	return config
}

func (jp *JsonParser) readSignatureConfig(descriptor map[string]interface{}) *signatureConfig {
	signatureMethod := jp.readString("signatureMethod", "UNSIGNED", descriptor)
	signatureCertificate := jp.readString("signatureCertificate", "", descriptor)

	config := &signatureConfig{}
	switch signatureMethod {
	case "UNSIGNED":
		config.signatureMethod = bacc.SIGMET_UNSINGED

	case "RSA-PRIVATE":
		config.signatureMethod = bacc.SIGMET_RSA_PRIVATE
		config.signatureCertificate = signatureCertificate

	default:
		panic(errors.New("illegal signature method selected"))
	}

	if config.signatureMethod == bacc.SIGMET_RSA_PRIVATE && config.signatureCertificate == "" {
		panic(errors.New("missing key on encryption configuration"))
	}

	return config
}
