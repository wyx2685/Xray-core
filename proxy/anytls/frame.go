package anytls

import (
	"encoding/binary"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
)

const (
	// cmds
	cmdWaste               = 0  // Paddings
	cmdSYN                 = 1  // stream open
	cmdPSH                 = 2  // data push
	cmdFIN                 = 3  // stream close, a.k.a EOF mark
	cmdSettings            = 4  // Settings (Client send to Server)
	cmdAlert               = 5  // Alert
	cmdUpdatePaddingScheme = 6  // update padding scheme
	cmdSYNACK              = 7  // Server reports to the client that the stream has been opened
	cmdHeartRequest        = 8  // Keep alive command
	cmdHeartResponse       = 9  // Keep alive command
	cmdServerSettings      = 10 // Settings (Server send to client)
)

// frameWriter handles writing ANYTLS protocol frames
type frameWriter struct {
	bw     *buf.BufferedWriter
	header [7]byte // Reusable header buffer
}

func newFrameWriter(bw *buf.BufferedWriter) *frameWriter {
	return &frameWriter{bw: bw}
}

const maxFramePayload = 0xffff

func (w *frameWriter) write(cmd byte, sid uint32, data []byte) error {
	if len(data) > maxFramePayload {
		return errors.New("anytls: frame payload too large")
	}
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

func (w *frameWriter) writeMultiBuffer(cmd byte, sid uint32, mb buf.MultiBuffer) error {
	if mb.IsEmpty() {
		return nil
	}
	if mb.Len() > maxFramePayload {
		return errors.New("anytls: frame payload too large")
	}
	w.header[0] = cmd
	binary.BigEndian.PutUint32(w.header[1:5], sid)
	binary.BigEndian.PutUint16(w.header[5:7], uint16(mb.Len()))

	if _, err := w.bw.Write(w.header[:]); err != nil {
		return err
	}

	return w.bw.WriteMultiBuffer(mb)
}

func (w *frameWriter) flush() error {
	return w.bw.Flush()
}
