package logger

import (
	"fmt"
	"os"
	"sync"
)

const (
	defaultMaxSizeMB  = 100
	defaultMaxBackups = 3
	megabyte          = 1024 * 1024
)

// rollingWriter implements io.Writer with size-based log rotation.
// When the current log file exceeds maxSize, it is rotated:
//
//	anygo.log       → anygo.log.1
//	anygo.log.1     → anygo.log.2
//	...             → ...
type rollingWriter struct {
	mu         sync.Mutex
	file       *os.File
	filePath   string
	maxSize    int64
	size       int64
	maxBackups int
}

// newRollingWriter opens a log file for writing with rotation support.
func newRollingWriter(filePath string, maxSizeMB int, maxBackups int) (*rollingWriter, error) {
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}

	if maxSizeMB <= 0 {
		maxSizeMB = defaultMaxSizeMB
	}
	if maxBackups <= 0 {
		maxBackups = defaultMaxBackups
	}

	return &rollingWriter{
		file:       f,
		filePath:   filePath,
		maxSize:    int64(maxSizeMB) * megabyte,
		size:       fi.Size(),
		maxBackups: maxBackups,
	}, nil
}

func (w *rollingWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.size >= w.maxSize {
		if err := w.rotate(); err != nil {
			fmt.Fprintf(os.Stderr, "log rotation failed: %v\n", err)
		}
	}

	n, err = w.file.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *rollingWriter) rotate() error {
	if err := w.file.Close(); err != nil {
		return err
	}

	// Remove the oldest backup
	os.Remove(fmt.Sprintf("%s.%d", w.filePath, w.maxBackups))

	// Shift backups: .2 → .3, .1 → .2
	for i := w.maxBackups - 1; i >= 1; i-- {
		oldName := fmt.Sprintf("%s.%d", w.filePath, i)
		newName := fmt.Sprintf("%s.%d", w.filePath, i+1)
		os.Rename(oldName, newName) // ignore error if source doesn't exist
	}

	// Rename current to .1
	if err := os.Rename(w.filePath, w.filePath+".1"); err != nil {
		return err
	}

	// Create fresh log file
	f, err := os.OpenFile(w.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	w.file = f
	w.size = 0
	return nil
}

func (w *rollingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.file.Close()
}
