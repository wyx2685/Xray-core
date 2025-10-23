package anytls

import (
	"context"
	"encoding/binary"
	"io"

	"github.com/xtls/xray-core/common/buf"
)

const (
	cmdSettings            = 4
	cmdSYN                 = 1
	cmdSYNACK              = 7
	cmdPSH                 = 2
	cmdFIN                 = 3
	cmdWaste               = 0
	cmdHeartRequest        = 8
	cmdHeartResponse       = 9
	cmdServerSettings      = 10
	cmdUpdatePaddingScheme = 6
	cmdAlert               = 5
)

// frameReader 帧读取器，保持 header buffer 复用以减少分配
type frameReader struct {
	br     *buf.BufferedReader
	ctx    context.Context
	header [7]byte // cmd(1) + sid(4) + length(2)
}

func newFrameReader(br *buf.BufferedReader, ctx context.Context) *frameReader {
	return &frameReader{br: br, ctx: ctx}
}

// read 读取一个完整帧，返回 cmd, sid, data
func (r *frameReader) read() (cmd byte, sid uint32, data []byte, err error) {
	// 读取固定 7 字节帧头
	_, err = io.ReadFull(r.br, r.header[:])
	if err != nil {
		return 0, 0, nil, err
	}

	cmd = r.header[0]
	sid = binary.BigEndian.Uint32(r.header[1:5])
	length := binary.BigEndian.Uint16(r.header[5:7])

	if length > 0 {
		data = make([]byte, length)
		_, err = io.ReadFull(r.br, data)
		if err != nil {
			return cmd, sid, nil, err
		}
	}

	return cmd, sid, data, nil
}

// frameWriter handles writing ANYTLS protocol frames
type frameWriter struct {
	bw     *buf.BufferedWriter
	header [7]byte // Reusable header buffer
}

func newFrameWriter(bw *buf.BufferedWriter) *frameWriter {
	return &frameWriter{bw: bw}
}

func (w *frameWriter) write(cmd byte, sid uint32, data []byte) error {
	w.header[0] = cmd
	binary.BigEndian.PutUint32(w.header[1:5], sid)
	binary.BigEndian.PutUint16(w.header[5:7], uint16(len(data)))

	if _, err := w.bw.Write(w.header[:]); err != nil {
		return err
	}

	if len(data) > 0 {
		// Flush header first if data is large (>= 8KB)
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
