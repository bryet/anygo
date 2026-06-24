package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// Level represents log severity
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

var currentLevel = LevelInfo

// ParseLevel parses a level string from config
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug, nil
	case "info", "":
		return LevelInfo, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	default:
		return LevelInfo, fmt.Errorf("unknown log level %q, supported: debug/info/warn/error", s)
	}
}

// Init initializes the logging system with log rotation.
// Log file is written to anygo.log alongside the binary, also outputs to stdout.
// Falls back to stdout-only if file cannot be created.
// Uses default rotation: 100 MB max size, 3 backups.
func Init(levelStr string) {
	InitWithRotation(levelStr, defaultMaxSizeMB, defaultMaxBackups)
}

// InitWithRotation initializes the logging system with configurable log rotation.
// maxSizeMB: maximum log file size in megabytes before rotation (0 = use default 100)
// maxBackups: number of backup files to keep (0 = use default 3)
func InitWithRotation(levelStr string, maxSizeMB, maxBackups int) {
	level, err := ParseLevel(levelStr)
	if err != nil {
		log.Printf("warning: %v, using default level info", err)
		level = LevelInfo
	}
	currentLevel = level

	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	execPath, err := os.Executable()
	if err != nil {
		log.SetOutput(os.Stdout)
		Warn("failed to get executable path, logging to stdout only: %v", err)
		return
	}

	logPath := filepath.Join(filepath.Dir(execPath), "anygo.log")
	rw, err := newRollingWriter(logPath, maxSizeMB, maxBackups)
	if err != nil {
		log.SetOutput(os.Stdout)
		Warn("failed to create log file %s, logging to stdout only: %v", logPath, err)
		return
	}

	log.SetOutput(io.MultiWriter(os.Stdout, rw))
	Info("log file: %s (max %dMB, %d backups)  level: %s", logPath, maxSizeMB, maxBackups, levelStr)
}

func Debug(format string, args ...any) {
	if currentLevel <= LevelDebug {
		log.Printf("[DEBUG] "+format, args...)
	}
}

func Info(format string, args ...any) {
	if currentLevel <= LevelInfo {
		log.Printf("[INFO]  "+format, args...)
	}
}

func Warn(format string, args ...any) {
	if currentLevel <= LevelWarn {
		log.Printf("[WARN]  "+format, args...)
	}
}

func Error(format string, args ...any) {
	if currentLevel <= LevelError {
		log.Printf("[ERROR] "+format, args...)
	}
}

func Fatal(format string, args ...any) {
	log.Fatalf("[FATAL] "+format, args...)
}