package util

import (
	"fmt"
	"io"
)

// FormatBytes formats a byte count as a human-readable string.
func FormatBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2fGB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.2fMB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.2fKB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
}

// EqualBytes performs a constant-time comparison of two byte slices.
// Returns true if they are equal in length and content.
func EqualBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// RelayWithStats performs bidirectional copy between two io.ReadWriter
// connections, returning the number of bytes transferred in each direction.
// Returns (bytesAtoB, bytesBtoA).
func RelayWithStats(a, b io.ReadWriter) (int64, int64) {
	var bytesAtoB, bytesBtoA int64
	done := make(chan struct{}, 2)

	go func() {
		n, _ := io.Copy(b, a)
		bytesAtoB = n
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(a, b)
		bytesBtoA = n
		done <- struct{}{}
	}()

	<-done
	<-done
	return bytesAtoB, bytesBtoA
}
