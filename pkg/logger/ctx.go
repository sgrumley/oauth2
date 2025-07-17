package logger

import (
	"context"
	"log/slog"
	"os"
)

type ctxKey struct{}

func AddLoggerContext(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, logger)
}

func LoggerFromContext(ctx context.Context) (*slog.Logger, bool) {
	logger, ok := ctx.Value(ctxKey{}).(*slog.Logger)
	return logger, ok
}

func FromContext(ctx context.Context) *slog.Logger {
	logger, ok := LoggerFromContext(ctx)
	if !ok {
		return NewLogger().Logger
	}
	return logger
}

func Debug(ctx context.Context, msg string, attrs ...any) {
	FromContext(ctx).Debug(msg, attrs...)
}

func Info(ctx context.Context, msg string, attrs ...any) {
	FromContext(ctx).Info(msg, attrs...)
}

func Error(ctx context.Context, msg string, err error) {
	FromContext(ctx).Error(msg, slog.Any("error", err))
}

func Fatal(ctx context.Context, msg string, err error) {
	Error(ctx, msg, err)
	os.Exit(1)
}
