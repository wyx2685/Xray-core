package anytls

import (
	"context"
	"encoding/binary"
	"io"

	"github.com/xtls/xray-core/common/buf"
)

// frameReader handles reading ANYTLS protocol frames
type frameReader struct {
	br     *buf.BufferedReader
	ctx    context.Context
	header [7]byte // Reusable header buffer to reduce allocations
}

func newFrameReader(br *buf.BufferedReader, ctx context.Context) *frameReader {
	return &frameReader{br: br, ctx: ctx}
}

func (r *frameReader) read() (cmd byte, sid uint32, data []byte, err error) {
	if _, err = io.ReadFull(r.br, r.header[:]); err != nil {
		return
	}
	cmd = r.header[0]
	sid = binary.BigEndian.Uint32(r.header[1:5])
	l := binary.BigEndian.Uint16(r.header[5:7])
	if l > 0 {
		data = make([]byte, int(l))
		if _, err = io.ReadFull(r.br, data); err != nil {
			return
		}
	}
	return
}

// frameWriter handles writing ANYTLS protocol frames
type frameWriter struct {
	bw     *buf.BufferedWriter
	header [7]byte // Reusable header buffer to reduce allocations
}

func newFrameWriter(bw *buf.BufferedWriter) *frameWriter {
	return &frameWriter{bw: bw}
}

func (w *frameWriter) write(cmd byte, sid uint32, data []byte) error {
	// Write header using reusable buffer
	w.header[0] = cmd
	binary.BigEndian.PutUint32(w.header[1:5], sid)
	binary.BigEndian.PutUint16(w.header[5:7], uint16(len(data)))

	if _, err := w.bw.Write(w.header[:]); err != nil {
		return err
	}

	// Write data if present
	if len(data) > 0 {
		// If data is large, flush header first to avoid "buffer is full" error
		// BufferedWriter buffer size is 8KB, so flush before writing >= 8KB data
		if len(data) >= 8192 {
			if err := w.bw.Flush(); err != nil {
				return err
			}
		}
		_, err := w.bw.Write(data)
		return err
	}

	return nil
}

func (w *frameWriter) flush() error {
	return w.bw.Flush()
}
