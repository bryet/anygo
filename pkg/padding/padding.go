package padding

import (
	"crypto/rand"
	"encoding/binary"
	"io"
)

// Config padding配置
type Config struct {
	Templates []int
}

// DefaultConfig 默认padding模板
var DefaultConfig = Config{
	Templates: []int{64, 128, 256, 512, 1024, 1440, 2048},
}

// Writer 写入时附加padding，帧格式：[2字节padding长度][原始数据][随机padding]
type Writer struct {
	w         io.Writer
	templates []int
}

func NewWriter(w io.Writer, cfg Config) *Writer {
	return &Writer{w: w, templates: cfg.Templates}
}

func (pw *Writer) Write(data []byte) (int, error) {
	// 选择合适的模板长度
	targetLen := pw.chooseTemplate(len(data) + 2)
	paddingLen := targetLen - len(data) - 2
	if paddingLen < 0 {
		paddingLen = 0
	}

	// 构造帧
	frame := make([]byte, 2+len(data)+paddingLen)
	binary.BigEndian.PutUint16(frame[:2], uint16(paddingLen))
	copy(frame[2:], data)
	if paddingLen > 0 {
		if _, err := rand.Read(frame[2+len(data):]); err != nil {
			return 0, err
		}
	}

	if _, err := pw.w.Write(frame); err != nil {
		return 0, err
	}
	return len(data), nil
}

func (pw *Writer) chooseTemplate(n int) int {
	for _, t := range pw.templates {
		if t >= n {
			return t
		}
	}
	// 超出最大模板，按1440对齐
	return ((n + 1439) / 1440) * 1440
}

// Reader 读取时剥离padding
type Reader struct {
	r io.Reader
}

func NewReader(r io.Reader) *Reader {
	return &Reader{r: r}
}

func (pr *Reader) Read(buf []byte) (int, error) {
	// 读2字节：padding长度
	header := make([]byte, 2)
	if _, err := io.ReadFull(pr.r, header); err != nil {
		return 0, err
	}
	paddingLen := int(binary.BigEndian.Uint16(header))

	// 读原始数据
	n, err := pr.r.Read(buf)
	if err != nil {
		return n, err
	}

	// 丢弃padding
	if paddingLen > 0 {
		discard := make([]byte, paddingLen)
		if _, err := io.ReadFull(pr.r, discard); err != nil {
			return n, err
		}
	}

	return n, nil
}
