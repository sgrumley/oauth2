package logger

import (
	"log/slog"
	"os"
	"time"

	"github.com/lmittmann/tint"
)

type Logger struct {
	*slog.Logger
}

type Level slog.Level

const (
	LevelInfo  Level = Level(slog.LevelInfo)
	LevelError Level = Level(slog.LevelError)
	LevelWarn  Level = Level(slog.LevelWarn)
	LevelDebug Level = Level(slog.LevelDebug)
)

type Handler string

const (
	HandlerJSON Handler = "json"
	HandlerText Handler = "text"
	HandlerTint Handler = "tint"
)

type (
	Option        func(*LoggerOptions)
	LoggerOptions struct {
		level  Level
		format Handler
		output *os.File
		source bool
	}
)

func WithLevel(level Level) Option {
	return func(opts *LoggerOptions) {
		opts.level = level
	}
}

func WithFormat(format Handler) Option {
	return func(opts *LoggerOptions) {
		opts.format = format
	}
}

func WithSource(s bool) Option {
	return func(opts *LoggerOptions) {
		opts.source = s
	}
}

func WithOutput(out *os.File) Option {
	return func(opts *LoggerOptions) {
		opts.output = out
	}
}

func NewLogger(options ...Option) *Logger {
	opts := LoggerOptions{
		level:  LevelInfo,
		format: HandlerTint,
		output: os.Stdout,
		source: false,
	}

	for _, opt := range options {
		opt(&opts)
	}

	handlerPreset := getHandler(opts)
	logger := slog.New(handlerPreset)
	// this allows access via importing slog, however it is better to pass
	// 	the logger where you can to avoid modifying the global instance
	slog.SetDefault(logger)
	return &Logger{
		slog.New(handlerPreset),
	}
}

func getHandler(opts LoggerOptions) slog.Handler {
	baseOpts := &slog.HandlerOptions{
		AddSource: opts.source,
		Level:     slog.Level(opts.level),
	}

	switch opts.format {
	case HandlerJSON:
		return slog.NewJSONHandler(opts.output, baseOpts)

	case HandlerText:
		return slog.NewTextHandler(opts.output, baseOpts)

	case HandlerTint:
		w := os.Stderr
		return tint.NewHandler(w, &tint.Options{
			AddSource:  false,
			Level:      slog.LevelDebug,
			TimeFormat: time.Kitchen,
			NoColor:    false,
		})
	}

	return slog.NewTextHandler(opts.output, baseOpts)
}
