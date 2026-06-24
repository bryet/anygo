package padding

import (
	"strings"
	"testing"
)

func TestDefault(t *testing.T) {
	s := Default()
	if s == nil {
		t.Fatal("Default() returned nil")
	}
	if s.Stop != 8 {
		t.Errorf("Stop = %d, want 8", s.Stop)
	}
	if len(s.Rules) == 0 {
		t.Error("Default scheme has no rules")
	}
	// Default should be a singleton
	s2 := Default()
	if s != s2 {
		t.Error("Default() should return the same instance")
	}
}

func TestParseValid(t *testing.T) {
	text := `stop=3
0=30-30
1=100-400
2=400-500,c,500-1000`
	s, err := Parse(text)
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if s.Stop != 3 {
		t.Errorf("Stop = %d, want 3", s.Stop)
	}
	if segs, ok := s.Rules[0]; !ok || len(segs) != 1 || segs[0].Min != 30 {
		t.Errorf("Rule 0 parsed incorrectly: %+v", segs)
	}
	if segs, ok := s.Rules[2]; !ok || len(segs) != 3 {
		t.Errorf("Rule 2 should have 3 segments, got %d", len(segs))
	}
}

func TestParseDefaultScheme(t *testing.T) {
	s, err := Parse(DefaultSchemeText)
	if err != nil {
		t.Fatalf("Parse(DefaultSchemeText) error: %v", err)
	}
	if s.Stop != 8 {
		t.Errorf("Stop = %d, want 8", s.Stop)
	}
	for i := 0; i < 8; i++ {
		if _, ok := s.Rules[i]; !ok {
			t.Errorf("Missing rule for packet %d", i)
		}
	}
}

func TestParseInvalidStop(t *testing.T) {
	_, err := Parse("stop=abc\n0=30-30")
	if err == nil {
		t.Error("Parse() with invalid stop should return an error")
	}
}

func TestParseComments(t *testing.T) {
	text := `# This is a comment
stop=2
0=30-30
# Another comment
1=100-200`
	s, err := Parse(text)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if s.Stop != 2 {
		t.Errorf("Stop = %d, want 2", s.Stop)
	}
}

func TestMD5(t *testing.T) {
	text := "stop=1\n0=30-30"
	s, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	md5 := s.MD5()
	if len(md5) != 32 {
		t.Errorf("MD5 hash should be 32 characters, got %d", len(md5))
	}
	// Same scheme should produce same MD5
	s2, _ := Parse(text)
	if s.MD5() != s2.MD5() {
		t.Error("Same scheme text should produce same MD5")
	}
}

func TestRaw(t *testing.T) {
	text := "stop=1\n0=30-30"
	s, _ := Parse(text)
	raw := s.Raw()
	// Raw should match the original after trimming leading/trailing whitespace
	if raw != strings.TrimSpace(text) {
		t.Errorf("Raw() = %q, want %q", raw, text)
	}
}

func TestPadding0Size(t *testing.T) {
	s, _ := Parse("stop=2\n0=30-30\n1=100-200")
	size := s.Padding0Size()
	if size != 30 {
		t.Errorf("Padding0Size() = %d, want 30", size)
	}
}

func TestPadding0SizeDefault(t *testing.T) {
	s, _ := Parse("stop=2")
	size := s.Padding0Size()
	if size != 30 {
		t.Errorf("Padding0Size() with no rule 0 should be 30, got %d", size)
	}
}

func TestPadding0SizeCheck(t *testing.T) {
	s, _ := Parse("stop=2\n0=c,100-200")
	size := s.Padding0Size()
	if size != 0 {
		t.Errorf("Padding0Size() with 'c' checkpoint should be 0, got %d", size)
	}
}

func TestRandInRange(t *testing.T) {
	const min, max = 10, 100
	for i := 0; i < 100; i++ {
		v := RandInRange(min, max)
		if v < min || v > max {
			t.Errorf("RandInRange(%d, %d) = %d, out of range", min, max, v)
		}
	}
}

func TestRandInRangeEqual(t *testing.T) {
	v := RandInRange(5, 5)
	if v != 5 {
		t.Errorf("RandInRange(5, 5) = %d, want 5", v)
	}
}

func TestRandBytes(t *testing.T) {
	b := RandBytes(32)
	if len(b) != 32 {
		t.Errorf("RandBytes(32) returned %d bytes", len(b))
	}
	// Random bytes should not all be zero
	allZero := true
	for _, v := range b {
		if v != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("RandBytes(32) returned all zeros (extremely unlikely with crypto/rand)")
	}
}
