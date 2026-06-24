package util

import (
	"bytes"
	"testing"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		n    int64
		want string
	}{
		{0, "0B"},
		{1, "1B"},
		{512, "512B"},
		{1024, "1.00KB"},
		{1536, "1.50KB"},
		{1048576, "1.00MB"},
		{1073741824, "1.00GB"},
		{2147483648, "2.00GB"},
	}
	for _, tt := range tests {
		got := FormatBytes(tt.n)
		if got != tt.want {
			t.Errorf("FormatBytes(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

func TestEqualBytes(t *testing.T) {
	tests := []struct {
		a, b []byte
		want bool
	}{
		{nil, nil, true},
		{[]byte{}, []byte{}, true},
		{[]byte{1, 2, 3}, []byte{1, 2, 3}, true},
		{[]byte{1, 2, 3}, []byte{1, 2}, false},
		{[]byte{1, 2, 3}, []byte{1, 2, 4}, false},
		{[]byte{0, 0, 0}, []byte{0, 0, 0}, true},
		{[]byte{0xff}, []byte{0x00}, false},
	}
	for _, tt := range tests {
		got := EqualBytes(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("EqualBytes(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestRelayWithStats(t *testing.T) {
	// Create two connected byte buffers using io.Pipe
	// We'll manually relay between them
	dataAtoB := []byte("hello from A to B")
	dataBtoA := []byte("hello from B to A")

	// Use bytes.Buffer as ReadWriter
	bufA := bytes.NewBuffer(nil)
	bufB := bytes.NewBuffer(nil)

	// Pre-fill data to simulate each side having data to send
	bufA.Write(dataAtoB)
	bufB.Write(dataBtoA)

	// RelayWithStats drains both and then returns
	// After relay: bufA should contain dataBtoA, bufB should contain dataAtoB
	in, out := RelayWithStats(bufA, bufB)

	if in != int64(len(dataAtoB)) {
		t.Errorf("bytesAtoB = %d, want %d", in, len(dataAtoB))
	}
	if out != int64(len(dataBtoA)) {
		t.Errorf("bytesBtoA = %d, want %d", out, len(dataBtoA))
	}
	// Verify data ended up on the correct sides
	if !bytes.Equal(bufA.Bytes()[:len(dataBtoA)], dataBtoA) {
		t.Errorf("bufA = %q, want %q", bufA.Bytes()[:len(dataBtoA)], dataBtoA)
	}
	if !bytes.Equal(bufB.Bytes()[:len(dataAtoB)], dataAtoB) {
		t.Errorf("bufB = %q, want %q", bufB.Bytes()[:len(dataAtoB)], dataAtoB)
	}
}
