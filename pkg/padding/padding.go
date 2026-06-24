package padding

import (
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
)

// DefaultSchemeText: default PaddingScheme text (official default)
const DefaultSchemeText = `stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000`

// Segment: a single padding segment strategy
type Segment struct {
	Min   int
	Max   int
	Check bool // true means this is the 'c' checkpoint
}

// Scheme: complete PaddingScheme
type Scheme struct {
	Stop  int               // only process packets 0 to Stop-1
	Rules map[int][]Segment // per-packet segment strategy list
	raw   string            // original text
}

// MD5 returns the md5 (lowercase hex) of the raw scheme text, for cmdSettings
func (s *Scheme) MD5() string {
	h := md5.Sum([]byte(s.raw))
	return fmt.Sprintf("%x", h)
}

// Raw returns the raw scheme text, for cmdUpdatePaddingScheme
func (s *Scheme) Raw() string {
	return s.raw
}

// Parse parses PaddingScheme text
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

// fix: use sync.Once to cache default scheme, avoid re-parsing on every Default() call
var (
	defaultSchemeOnce sync.Once
	defaultScheme     *Scheme
)

// Default returns the parsed default PaddingScheme (global singleton, parsed once)
func Default() *Scheme {
	defaultSchemeOnce.Do(func() {
		var err error
		defaultScheme, err = Parse(DefaultSchemeText)
		if err != nil {
			// DefaultSchemeText is a hardcoded valid value; this should never fail
			panic(fmt.Sprintf("parse default padding scheme failed: %v", err))
		}
	})
	return defaultScheme
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

// RandInRange returns a random integer in [min, max]
func RandInRange(min, max int) int {
	if min >= max {
		return min
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	return min + int(n.Int64())
}

// RandBytes generates n bytes of random data
func RandBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// Padding0Size returns the padding0 size based on rule 0 of the scheme
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