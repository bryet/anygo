package padding

import (
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// DefaultSchemeText 默认PaddingScheme文本（官方默认值）
const DefaultSchemeText = `stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000`

// Segment 一个分段策略单元
type Segment struct {
	Min   int
	Max   int
	Check bool // true表示这是'c'检查符号
}

// Scheme 完整的PaddingScheme
type Scheme struct {
	Stop  int               // 只处理第0~Stop-1个包
	Rules map[int][]Segment // 每个包的分段策略列表
	raw   string            // 原始文本
}

// MD5 返回scheme原始文本的md5（小写hex），用于cmdSettings上报
func (s *Scheme) MD5() string {
	h := md5.Sum([]byte(s.raw))
	return fmt.Sprintf("%x", h)
}

// Raw 返回原始scheme文本，用于cmdUpdatePaddingScheme下发
func (s *Scheme) Raw() string {
	return s.raw
}

// Parse 解析PaddingScheme文本
func Parse(text string) (*Scheme, error) {
	scheme := &Scheme{
		Stop:  8,
		Rules: make(map[int][]Segment),
		raw:   text,
	}

	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		eqIdx := strings.IndexByte(line, '=')
		if eqIdx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eqIdx])
		val := strings.TrimSpace(line[eqIdx+1:])

		if key == "stop" {
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("invalid stop value: %s", val)
			}
			scheme.Stop = n
			continue
		}

		pktIdx, err := strconv.Atoi(key)
		if err != nil {
			continue
		}

		segments, err := parseSegments(val)
		if err != nil {
			return nil, fmt.Errorf("invalid rule for packet %d: %v", pktIdx, err)
		}
		scheme.Rules[pktIdx] = segments
	}

	return scheme, nil
}

// Default 返回解析好的默认PaddingScheme
func Default() *Scheme {
	s, _ := Parse(DefaultSchemeText)
	return s
}

func parseSegments(s string) ([]Segment, error) {
	parts := strings.Split(s, ",")
	var segs []Segment

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "c" {
			segs = append(segs, Segment{Check: true})
			continue
		}

		dashIdx := strings.IndexByte(p, '-')
		if dashIdx < 0 {
			return nil, fmt.Errorf("invalid segment: %s", p)
		}

		minVal, err := strconv.Atoi(strings.TrimSpace(p[:dashIdx]))
		if err != nil {
			return nil, fmt.Errorf("invalid min in segment %s: %v", p, err)
		}
		maxVal, err := strconv.Atoi(strings.TrimSpace(p[dashIdx+1:]))
		if err != nil {
			return nil, fmt.Errorf("invalid max in segment %s: %v", p, err)
		}

		segs = append(segs, Segment{Min: minVal, Max: maxVal})
	}

	return segs, nil
}

// RandInRange 返回[min, max]范围内的随机整数
func RandInRange(min, max int) int {
	if min >= max {
		return min
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	return min + int(n.Int64())
}

// RandBytes 生成n字节随机数据
func RandBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// Padding0Size 根据scheme第0条规则返回padding0大小
func (s *Scheme) Padding0Size() int {
	segs, ok := s.Rules[0]
	if !ok || len(segs) == 0 {
		return 30
	}
	seg := segs[0]
	if seg.Check {
		return 0
	}
	return RandInRange(seg.Min, seg.Max)
}
