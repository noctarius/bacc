package bacc

import (
	"github.com/spf13/afero"
	"time"
	"os"
	"syscall"
	"strings"
	"path/filepath"
	"errors"
	"io"
	"sync/atomic"
)

var errOnlyAbsPath = errors.New("only absolute paths are allowed inside a bacc file")

type baccFs struct {
	archive Archive
}

func NewBaccFilesystem(archivePath string, keyManger KeyManager) (afero.Fs, error) {
	reader := NewReader(keyManger)

	archive, err := reader.ReadArchive(archivePath)
	if err != nil {
		return nil, err
	}

	return &baccFs{
		archive: archive,
	}, nil
}

func (bf *baccFs) Open(name string) (afero.File, error) {
	return bf.OpenFile(name, os.O_RDONLY, os.ModePerm)
}

func (bf *baccFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	if flag&(os.O_WRONLY|syscall.O_RDWR|os.O_APPEND|os.O_CREATE|os.O_TRUNC) != 0 {
		return nil, syscall.EPERM
	}

	if !filepath.IsAbs(name) {
		return nil, errOnlyAbsPath
	}

	name = name[1:]
	segments := strings.Split(name, "/")

	entry := bf.archive.RootEntry()
	for segIndex := 1; segIndex < len(segments); segIndex++ {
		for _, child := range entry.Entries() {
			if child.Name() != segments[segIndex] {
				continue
			}

			if child.EntryType() == ENTRY_TYPE_FILE {
				if segIndex != len(segments)-1 {
					return nil, os.ErrNotExist
				}
			}

			if segIndex == len(segments)-1 {
				return bf.createFile(child)
			}

			entry = child.(ArchiveFolder)
			break
		}
	}
	return nil, os.ErrNotExist
}

func (bf *baccFs) Stat(name string) (os.FileInfo, error) {
	file, err := bf.Open(name)
	if err != nil {
		return nil, err
	}
	return file.Stat()
}

func (bf *baccFs) Name() string {
	return "BaccFs"
}

func (bf *baccFs) Create(name string) (afero.File, error) {
	return nil, syscall.EPERM
}

func (bf *baccFs) Mkdir(name string, perm os.FileMode) error {
	return syscall.EPERM
}

func (bf *baccFs) MkdirAll(path string, perm os.FileMode) error {
	return syscall.EPERM
}

func (bf *baccFs) Remove(name string) error {
	return syscall.EPERM
}

func (bf *baccFs) RemoveAll(path string) error {
	return syscall.EPERM
}

func (bf *baccFs) Rename(oldname, newname string) error {
	return syscall.EPERM
}

func (bf *baccFs) Chmod(name string, mode os.FileMode) error {
	return syscall.EPERM
}

func (bf *baccFs) Chtimes(name string, atime time.Time, mtime time.Time) error {
	return syscall.EPERM
}

func (bf *baccFs) Close() error {
	return bf.archive.Close()
}

func (bf *baccFs) createFileInfo(entry ArchiveEntry) *baccFileInfo {
	dir := false
	size := int64(0)

	switch c := entry.(type) {
	case ArchiveFolder:
		dir = true
	case ArchiveFile:
		size = int64(c.UncompressedSize())
	}

	t := time.Unix(0, int64(entry.Timestamp()))

	return &baccFileInfo{
		name: entry.Name(),
		dir:  dir,
		size: size,
		time: t,
	}
}

func (bf *baccFs) createFile(entry ArchiveEntry) (*baccFile, error) {
	return &baccFile{
		fs:       bf,
		name:     entry.Name(),
		entry:    entry,
		fileInfo: bf.createFileInfo(entry),
	}, nil
}

type baccFile struct {
	name     string
	entry    ArchiveEntry
	fileInfo os.FileInfo
	reader   EntryReader
	offset   int64
	fs       *baccFs
}

func (bf *baccFile) Close() error {
	return nil
}

func (bf *baccFile) Read(p []byte) (int, error) {
	n, err := bf.fileAccess(p, bf.offset, func(reader io.ReaderAt, offset int64, p []byte) (int, error) {
		return reader.ReadAt(p, offset)
	})

	if err != nil {
		return 0, err
	}

	bf.offset += int64(n)
	return n, nil
}

func (bf *baccFile) ReadAt(p []byte, off int64) (int, error) {
	return bf.fileAccess(p, off, func(reader io.ReaderAt, offset int64, p []byte) (int, error) {
		return reader.ReadAt(p, offset)
	})
}

func (bf *baccFile) Seek(offset int64, whence int) (int64, error) {
	if _, ok := bf.ArchiveEntry().(ArchiveFile); ok {
		switch whence {
		case io.SeekStart:
			atomic.StoreInt64(&bf.offset, offset)
		case io.SeekCurrent:
			bf.offset += offset
		case io.SeekEnd:
			bf.offset = bf.fileInfo.Size() + offset
		}
		return offset, nil
	}
	return 0, os.ErrPermission
}

func (bf *baccFile) Write(p []byte) (n int, err error) {
	return 0, syscall.EPERM
}

func (bf *baccFile) WriteAt(p []byte, off int64) (n int, err error) {
	return 0, syscall.EPERM
}

func (bf *baccFile) Name() string {
	return bf.name
}

func (bf *baccFile) Readdir(count int) ([]os.FileInfo, error) {
	if f, ok := bf.ArchiveEntry().(ArchiveFolder); ok {
		entries := make([]os.FileInfo, len(f.Entries()))
		for i, entry := range f.Entries() {
			entries[i] = bf.fs.createFileInfo(entry)
		}
		return entries, nil
	}
	return nil, os.ErrPermission
}

func (bf *baccFile) Readdirnames(n int) ([]string, error) {
	if f, ok := bf.ArchiveEntry().(ArchiveFolder); ok {
		entries := make([]string, len(f.Entries()))
		for i, entry := range f.Entries() {
			entries[i] = entry.Name()
		}
		return entries, nil
	}
	return nil, os.ErrPermission
}

func (bf *baccFile) Stat() (os.FileInfo, error) {
	return bf.fileInfo, nil
}

func (bf *baccFile) Sync() error {
	return nil
}

func (bf *baccFile) Truncate(size int64) error {
	return syscall.EPERM
}

func (bf *baccFile) WriteString(s string) (ret int, err error) {
	return 0, syscall.EPERM
}

func (bf *baccFile) ArchiveEntry() ArchiveEntry {
	return bf.entry
}

func (bf *baccFile) fileAccess(p []byte, offset int64, fun func(reader io.ReaderAt, offset int64, p []byte) (int, error)) (int, error) {
	if f, ok := bf.ArchiveEntry().(ArchiveFile); ok {
		if bf.reader == nil {
			bf.reader = f.NewReader()
		}

		return fun(bf.reader, offset, p)
	}
	return 0, os.ErrPermission
}

type baccFileInfo struct {
	name string
	size int64
	time time.Time
	dir  bool
}

func (bfi *baccFileInfo) Name() string {
	return bfi.name
}

func (bfi *baccFileInfo) Size() int64 {
	return bfi.size
}

func (bfi *baccFileInfo) Mode() os.FileMode {
	return os.ModePerm
}

func (bfi *baccFileInfo) ModTime() time.Time {
	return bfi.time
}

func (bfi *baccFileInfo) IsDir() bool {
	return bfi.dir
}

func (bfi *baccFileInfo) Sys() interface{} {
	return nil
}
