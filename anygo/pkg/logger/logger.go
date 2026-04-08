package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// Level 日志级别
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

var currentLevel = LevelInfo

// ParseLevel 解析配置文件里的级别字符串
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
		return LevelInfo, fmt.Errorf("未知日志级别 %q，支持: debug/info/warn/error", s)
	}
}

// Init 初始化日志系统
// 日志文件固定写到程序所在目录下的 anygo.log，同时输出标准输出
// 若无法创建文件则退化为只写标准输出
func Init(levelStr string) {
	level, err := ParseLevel(levelStr)
	if err != nil {
		log.Printf("警告: %v，使用默认级别 info", err)
		level = LevelInfo
	}
	currentLevel = level

	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	execPath, err := os.Executable()
	if err != nil {
		log.SetOutput(os.Stdout)
		Warn("获取程序路径失败，日志仅输出到标准输出: %v", err)
		return
	}

	logPath := filepath.Join(filepath.Dir(execPath), "anygo.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.SetOutput(os.Stdout)
		Warn("无法创建日志文件 %s，日志仅输出到标准输出: %v", logPath, err)
		return
	}

	log.SetOutput(io.MultiWriter(os.Stdout, f))
	Info("日志文件: %s  级别: %s", logPath, levelStr)
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