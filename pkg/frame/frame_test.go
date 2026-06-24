package frame

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestWriteReadFrame(t *testing.T) {
	tests := []struct {
		name     string
		cmd      uint8
		streamID uint32
		data     []byte
	}{
		{"empty data", CmdSYN, 1, nil},
		{"with data", CmdPSH, 42, []byte("hello world")},
		{"large data", CmdPSH, 65535, bytes.Repeat([]byte("x"), 1000)},
		{"zero stream", CmdFIN, 0, []byte{0x00, 0xff}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteFrame(&buf, tt.cmd, tt.streamID, tt.data); err != nil {
				t.Fatalf("WriteFrame() error: %v", err)
			}

			frame, err := ReadFrame(&buf)
			if err != nil {
				t.Fatalf("ReadFrame() error: %v", err)
			}

			if frame.Command != tt.cmd {
				t.Errorf("Command = %d, want %d", frame.Command, tt.cmd)
			}
			if frame.StreamID != tt.streamID {
				t.Errorf("StreamID = %d, want %d", frame.StreamID, tt.streamID)
			}
			if !bytes.Equal(frame.Data, tt.data) {
				t.Errorf("Data = %v, want %v", frame.Data, tt.data)
			}
		})
	}
}

func TestReadFrameShortHeader(t *testing.T) {
	buf := bytes.NewBuffer([]byte{0x01, 0x00}) // only 2 bytes
	_, err := ReadFrame(buf)
	if err == nil {
		t.Error("ReadFrame() with short header should return an error")
	}
}

func TestReadFrameShortData(t *testing.T) {
	// Header says 10 bytes of data, but only 5 provided
	buf := make([]byte, HeaderSize+5)
	buf[0] = CmdPSH                                    // command
	buf[1], buf[2], buf[3], buf[4] = 0, 0, 0, 1       // streamID = 1
	buf[5], buf[6] = 0, 10                             // dataLen = 10
	_, err := ReadFrame(bytes.NewReader(buf))
	if err == nil {
		t.Error("ReadFrame() with truncated data should return an error")
	}
}

func TestWriteReadAuth(t *testing.T) {
	password := "test-password-123"
	hash := sha256.Sum256([]byte(password))
	padding := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	var buf bytes.Buffer
	if err := WriteAuth(&buf, hash[:], padding); err != nil {
		t.Fatalf("WriteAuth() error: %v", err)
	}

	readHash, readPadding, err := ReadAuth(&buf)
	if err != nil {
		t.Fatalf("ReadAuth() error: %v", err)
	}

	if !bytes.Equal(readHash, hash[:]) {
		t.Errorf("Hash mismatch: got %x, want %x", readHash, hash[:])
	}
	if !bytes.Equal(readPadding, padding) {
		t.Errorf("Padding mismatch: got %x, want %x", readPadding, padding)
	}
}

func TestWriteReadAuthNoPadding(t *testing.T) {
	hash := sha256.Sum256([]byte("pw"))

	var buf bytes.Buffer
	if err := WriteAuth(&buf, hash[:], nil); err != nil {
		t.Fatalf("WriteAuth() error: %v", err)
	}

	_, readPadding, err := ReadAuth(&buf)
	if err != nil {
		t.Fatalf("ReadAuth() error: %v", err)
	}
	if len(readPadding) != 0 {
		t.Errorf("Expected empty padding, got %d bytes", len(readPadding))
	}
}

func TestReadAuthShortHeader(t *testing.T) {
	buf := bytes.NewBuffer([]byte{0x00}) // only 1 byte
	_, _, err := ReadAuth(buf)
	if err == nil {
		t.Error("ReadAuth() with short header should return an error")
	}
}

func TestAllCommandsDistinct(t *testing.T) {
	cmds := map[uint8]bool{}
	for _, c := range []uint8{
		CmdWaste, CmdSYN, CmdPSH, CmdFIN,
		CmdSettings, CmdAlert, CmdUpdatePaddingScheme,
		CmdSYNACK, CmdHeartRequest, CmdHeartResponse, CmdServerSettings,
	} {
		if cmds[c] {
			t.Errorf("Duplicate command value: %d", c)
		}
		cmds[c] = true
	}
}
