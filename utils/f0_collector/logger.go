package main

import (
	"io"
	"os"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Logger wraps logrus logger
type Logger struct {
	*logrus.Logger
}

// NewLogger creates a new logger instance
func NewLogger(config LoggingConfig, verbose bool) *Logger {
	log := logrus.New()

	// Set log level
	level := config.Level
	if verbose {
		level = "debug"
	}

	switch level {
	case "debug":
		log.SetLevel(logrus.DebugLevel)
	case "info":
		log.SetLevel(logrus.InfoLevel)
	case "warn":
		log.SetLevel(logrus.WarnLevel)
	case "error":
		log.SetLevel(logrus.ErrorLevel)
	default:
		log.SetLevel(logrus.InfoLevel)
	}

	// Set formatter
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
	})

	// Configure output writers
	var writers []io.Writer

	// Console output
	if config.Console {
		writers = append(writers, os.Stdout)
	}

	// File output with rotation
	if config.File != "" {
		fileWriter := &lumberjack.Logger{
			Filename:   config.File,
			MaxSize:    config.MaxSizeMB,
			MaxBackups: config.MaxBackups,
			Compress:   true,
		}
		writers = append(writers, fileWriter)
	}

	// Set multi-writer
	if len(writers) > 0 {
		log.SetOutput(io.MultiWriter(writers...))
	}

	return &Logger{Logger: log}
}
