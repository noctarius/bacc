package bacc

import "os"

type readerBuffer struct {
	file *os.File
}

func newReader(file *os.File) (*readerBuffer, error) {
	r := &readerBuffer{
		file: file,
	}
	return r, nil
}

func (r *readerBuffer) ReadAt(p []byte, off int64) (n int, err error) {
	return r.file.ReadAt(p, off)
}

func (r *readerBuffer) readUint8(offset int64) (uint8, error) {
	d := make([]byte, 1)
	_, err := r.file.ReadAt(d, offset)
	if err != nil {
		return 0, err
	}
	return uint8(d[0]), nil
}

func (r *readerBuffer) readUint16(offset int64) (uint16, error) {
	d := make([]byte, 2)
	_, err := r.file.ReadAt(d, offset)
	if err != nil {
		return 0, err
	}
	return uint16(d[1]) | uint16(d[0])<<8, nil
}

func (r *readerBuffer) readUint24(offset int64) (uint32, error) {
	d := make([]byte, 3)
	_, err := r.file.ReadAt(d, offset)
	if err != nil {
		return 0, err
	}
	return uint32(d[2]) | uint32(d[1])<<8 | uint32(d[0])<<16, nil
}

func (r *readerBuffer) readUint32(offset int64) (uint32, error) {
	d := make([]byte, 4)
	_, err := r.file.ReadAt(d, offset)
	if err != nil {
		return 0, err
	}
	return uint32(d[3]) | uint32(d[2])<<8 | uint32(d[1])<<16 | uint32(d[0])<<24, nil
}

func (r *readerBuffer) readUint64(offset int64) (uint64, error) {
	d := make([]byte, 8)
	_, err := r.file.ReadAt(d, offset)
	if err != nil {
		return 0, err
	}
	return uint64(d[7]) | uint64(d[6])<<8 | uint64(d[5])<<16 | uint64(d[4])<<24 |
		uint64(d[3])<<32 | uint64(d[2])<<40 | uint64(d[1])<<48 | uint64(d[0])<<56, nil
}
