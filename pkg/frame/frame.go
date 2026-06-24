package frame

import (
	"encoding/binary"
	"io"
)

// Command type definitions
const (
	// Version 1
	CmdWaste               uint8 = 0 // padding packet, silently discarded
	CmdSYN                 uint8 = 1 // open a new Stream
	CmdPSH                 uint8 = 2 // transmit data
	CmdFIN                 uint8 = 3 // close a Stream
	CmdSettings            uint8 = 4 // client→server: send client info
	CmdAlert               uint8 = 5 // server→client: alert and close session
	CmdUpdatePaddingScheme uint8 = 6 // server→client: push new PaddingScheme

	// Version 2
	CmdSYNACK         uint8 = 7  // server→client: confirm Stream outbound connection established
	CmdHeartRequest   uint8 = 8  // heartbeat request
	CmdHeartResponse  uint8 = 9  // heartbeat response
	CmdServerSettings uint8 = 10 // server→client: send server info
)

// Frame: session-layer frame
// format: | command uint8 | streamId uint32 BE | dataLen uint16 BE | data |
type Frame struct {
	Command  uint8
	StreamID uint32
	Data     []byte
}

// HeaderSize: fixed header size = 1+4+2 = 7 bytes
const HeaderSize = 7

// WriteFrame writes a frame to the writer
func WriteFrame(w io.Writer, cmd uint8, streamID uint32, data []byte) error {
	buf := make([]byte, HeaderSize+len(data))
	buf[0] = cmd
	binary.BigEndian.PutUint32(buf[1:5], streamID)
	binary.BigEndian.PutUint16(buf[5:7], uint16(len(data)))
	copy(buf[7:], data)
	_, err := w.Write(buf)
	return err
}

// ReadFrame reads a frame from the reader
func ReadFrame(r io.Reader) (*Frame, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	cmd := header[0]
	streamID := binary.BigEndian.Uint32(header[1:5])
	dataLen := binary.BigEndian.Uint16(header[5:7])

	var data []byte
	if dataLen > 0 {
		data = make([]byte, dataLen)
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, err
		}
	}

	return &Frame{
		Command:  cmd,
		StreamID: streamID,
		Data:     data,
	}, nil
}

// WriteAuth: write auth packet | sha256(password) 32B | padding0Len uint16 BE | padding0 |
func WriteAuth(w io.Writer, passwordHash []byte, padding0 []byte) error {
	buf := make([]byte, 32+2+len(padding0))
	copy(buf[:32], passwordHash)
	binary.BigEndian.PutUint16(buf[32:34], uint16(len(padding0)))
	copy(buf[34:], padding0)
	_, err := w.Write(buf)
	return err
}

// ReadAuth: read auth packet, returns passwordHash and padding0
func ReadAuth(r io.Reader) ([]byte, []byte, error) {
	// read 32-byte hash + 2-byte padding length
	header := make([]byte, 34)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, nil, err
	}

	passwordHash := header[:32]
	padding0Len := binary.BigEndian.Uint16(header[32:34])

	var padding0 []byte
	if padding0Len > 0 {
		padding0 = make([]byte, padding0Len)
		if _, err := io.ReadFull(r, padding0); err != nil {
			return nil, nil, err
		}
	}

	return passwordHash, padding0, nil
}
