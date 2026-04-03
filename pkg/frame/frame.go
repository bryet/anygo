package frame

import (
	"encoding/binary"
	"io"
)

// Command 类型定义
const (
	// Version 1
	CmdWaste               uint8 = 0 // 填充包，收到后无声丢弃
	CmdSYN                 uint8 = 1 // 打开新Stream
	CmdPSH                 uint8 = 2 // 传输数据
	CmdFIN                 uint8 = 3 // 关闭Stream
	CmdSettings            uint8 = 4 // 客户端→服务器：发送客户端信息
	CmdAlert               uint8 = 5 // 服务器→客户端：警告并关闭Session
	CmdUpdatePaddingScheme uint8 = 6 // 服务器→客户端：下发新PaddingScheme

	// Version 2
	CmdSYNACK         uint8 = 7  // 服务器→客户端：确认Stream出站连接已建立
	CmdHeartRequest   uint8 = 8  // 心跳请求
	CmdHeartResponse  uint8 = 9  // 心跳响应
	CmdServerSettings uint8 = 10 // 服务器→客户端：发送服务器信息
)

// Frame 会话层帧
// 格式：| command uint8 | streamId uint32 BE | dataLen uint16 BE | data |
type Frame struct {
	Command  uint8
	StreamID uint32
	Data     []byte
}

// HeaderSize 固定头部大小：1 + 4 + 2 = 7字节
const HeaderSize = 7

// WriteFrame 将帧写入writer
func WriteFrame(w io.Writer, cmd uint8, streamID uint32, data []byte) error {
	buf := make([]byte, HeaderSize+len(data))
	buf[0] = cmd
	binary.BigEndian.PutUint32(buf[1:5], streamID)
	binary.BigEndian.PutUint16(buf[5:7], uint16(len(data)))
	copy(buf[7:], data)
	_, err := w.Write(buf)
	return err
}

// ReadFrame 从reader读取一个帧
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

// WriteAuth 写认证包：| sha256(password) 32B | padding0Len uint16 BE | padding0 |
func WriteAuth(w io.Writer, passwordHash []byte, padding0 []byte) error {
	buf := make([]byte, 32+2+len(padding0))
	copy(buf[:32], passwordHash)
	binary.BigEndian.PutUint16(buf[32:34], uint16(len(padding0)))
	copy(buf[34:], padding0)
	_, err := w.Write(buf)
	return err
}

// ReadAuth 读认证包，返回passwordHash和padding0
func ReadAuth(r io.Reader) ([]byte, []byte, error) {
	// 读32字节hash + 2字节padding长度
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
