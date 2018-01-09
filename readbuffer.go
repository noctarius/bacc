package bacc

import "os"

type readerBuffer struct {
	file        *os.File
	chunkOffset int64
	chunkLength int16
	chunk       []byte
}

func newReader(file *os.File) (*readerBuffer, error) {
	r := &readerBuffer{
		file:  file,
		chunk: make([]byte, 1024),
	}
	if err := r.readChunk(0); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *readerBuffer) ReadAt(p []byte, off int64) (n int, err error) {
	if err := r.readBuffer(p, off); err != nil {
		return -1, err
	}
	return len(p), nil
}

func (r *readerBuffer) readBuffer(buffer []byte, offset int64) error {
	length := len(buffer)
	r.validateChunkOffset(offset, int64(length))
	buf, err := r.slice(offset, int64(len(buffer)))
	if err != nil {
		return err
	}
	copy(buffer, buf)
	return nil
}

func (r *readerBuffer) readUint8(offset int64) (uint8, error) {
	r.validateChunkOffset(offset, 1)
	return uint8(r.chunk[offset-r.chunkOffset]), nil
}

func (r *readerBuffer) readUint16(offset int64) (uint16, error) {
	buf, err := r.slice(offset, 4)
	if err != nil {
		return 0, err
	}
	return uint16(buf[1]) | uint16(buf[0])<<8, nil
}

func (r *readerBuffer) readUint24(offset int64) (uint32, error) {
	buf, err := r.slice(offset, 3)
	if err != nil {
		return 0, err
	}
	return uint32(buf[2]) | uint32(buf[1])<<8 | uint32(buf[0])<<16, nil
}

func (r *readerBuffer) readUint32(offset int64) (uint32, error) {
	buf, err := r.slice(offset, 4)
	if err != nil {
		return 0, err
	}
	return uint32(buf[3]) | uint32(buf[2])<<8 | uint32(buf[1])<<16 | uint32(buf[0])<<24, nil
}

func (r *readerBuffer) readUint64(offset int64) (uint64, error) {
	buf, err := r.slice(offset, 8)
	if err != nil {
		return 0, err
	}
	return uint64(buf[7]) | uint64(buf[6])<<8 | uint64(buf[5])<<16 | uint64(buf[4])<<24 |
		uint64(buf[3])<<32 | uint64(buf[2])<<40 | uint64(buf[1])<<48 | uint64(buf[0])<<56, nil
}

func (r *readerBuffer) readChunk(offset int64) error {
	r.chunkOffset = offset
	if length, err := r.file.ReadAt(r.chunk, offset); err != nil {
		return err
	} else {
		r.chunkLength = int16(length)
	}
	return nil
}

func (r *readerBuffer) validateChunkOffset(offset int64, length int64) error {
	if r.chunkOffset >= offset && r.chunkOffset <= offset+length {
		return nil
	}
	return r.readChunk(offset)
}

func (r *readerBuffer) slice(offset, length int64) ([]byte, error) {
	buffer := make([]byte, length)

	soffset, remaining := offset, length
	toffset := int64(0)
	for remaining > 0 {
		rlength := min(remaining, int64(len(r.chunk)))

		if err := r.validateChunkOffset(soffset, rlength); err != nil {
			return nil, err
		}

		start := soffset - r.chunkOffset
		end := start + rlength

		copy(buffer[toffset:toffset+rlength], r.chunk[start:end])

		soffset += rlength
		toffset += rlength
		remaining -= rlength
	}
	return buffer, nil
}
