package bacc

import "io"

type writeBuffer struct {
	offset int64
	writer io.WriterAt
	buffer [1024]byte
	marker int64
}

func newWriteBuffer(writer io.WriterAt) *writeBuffer {
	return &writeBuffer{offset: 0, writer: writer, marker: 0}
}

func (wb *writeBuffer) mark() {
	wb.marker = wb.offset
}

func (wb *writeBuffer) writtenSinceMarker() int64 {
	return wb.offset - wb.marker
}

func (wb *writeBuffer) skip(bytes int64) {
	wb.offset += bytes
}

func (wb *writeBuffer) Write(p []byte) (n int, err error) {
	n, err = wb.writer.WriteAt(p, wb.offset)
	if err != nil {
		return
	}
	wb.offset += int64(n)
	return
}

func (wb *writeBuffer) writeUint8(value uint8) (n int, err error) {
	wb.buffer[0] = value
	n, err = wb.writer.WriteAt(wb.buffer[:1], wb.offset)
	if err != nil {
		return
	}
	wb.offset++
	return
}

func (wb *writeBuffer) writeUint16(value uint16) (n int, err error) {
	wb.buffer[0] = byte(value >> 8)
	wb.buffer[1] = byte(value)
	n, err = wb.writer.WriteAt(wb.buffer[:2], wb.offset)
	if err != nil {
		return
	}
	wb.offset += 2
	return
}

func (wb *writeBuffer) writeUint24(value uint32) (n int, err error) {
	wb.buffer[0] = byte(value >> 16)
	wb.buffer[1] = byte(value >> 8)
	wb.buffer[2] = byte(value)
	n, err = wb.writer.WriteAt(wb.buffer[:3], wb.offset)
	if err != nil {
		return
	}
	wb.offset += 3
	return
}

func (wb *writeBuffer) writeUint32(value uint32) (n int, err error) {
	wb.buffer[0] = byte(value >> 24)
	wb.buffer[1] = byte(value >> 16)
	wb.buffer[2] = byte(value >> 8)
	wb.buffer[3] = byte(value)
	n, err = wb.writer.WriteAt(wb.buffer[:4], wb.offset)
	if err != nil {
		return
	}
	wb.offset += 4
	return
}

func (wb *writeBuffer) writeUint64(value uint64) (n int, err error) {
	wb.buffer[0] = byte(value >> 56)
	wb.buffer[1] = byte(value >> 48)
	wb.buffer[2] = byte(value >> 40)
	wb.buffer[3] = byte(value >> 32)
	wb.buffer[4] = byte(value >> 24)
	wb.buffer[5] = byte(value >> 16)
	wb.buffer[6] = byte(value >> 8)
	wb.buffer[7] = byte(value)
	n, err = wb.writer.WriteAt(wb.buffer[:8], wb.offset)
	if err != nil {
		return
	}
	wb.offset += 8
	return
}

func (wb *writeBuffer) writeUtf8(value string) (n int, err error) {
	data := []byte(value)
	wb.buffer[0] = 0x00

	written := 0
	n, err = wb.writer.WriteAt(data, wb.offset)
	if err != nil {
		return
	}

	written += n
	wb.offset += int64(len(data))

	wb.writer.WriteAt(wb.buffer[:1], wb.offset)
	if err != nil {
		return
	}

	written += n
	n = written

	wb.offset++
	return
}
