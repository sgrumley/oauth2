package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"

	"github.com/sgrumley/oauth/pkg/logger"
)

func ListenAndServe(ctx context.Context, server *http.Server, opts ...HandleExitOption) error {
	logger.Info(ctx, "starting server", slog.String("address", server.Addr))

	cfg := newConfig(server, opts...)

	GracefulDoneCh := HandleShutdown(ctx, cfg)

	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("server crashed with error: %w", err)
	}

	if err := <-GracefulDoneCh; err != nil {
		return err
	}

	return nil
}

func HandleShutdown(ctx context.Context, cfg *exitConfig) <-chan error {
	done := make(chan error, 1)
	exit := make(chan os.Signal, 1)

	signal.Notify(exit, cfg.trappedSignals...)

	go func() {
		select {
		case sig := <-exit:
			logger.Info(ctx, "shutting down server", slog.String("signal", sig.String()))

		case <-ctx.Done():
			logger.Info(ctx, "shutting down server", slog.String("reason", ctx.Err().Error()))
		}

		ctxTTL, cancel := context.WithTimeout(cfg.ctx, cfg.timeout)
		defer cancel()

		finished := make(chan error, 1)
		go func() {
			finished <- cfg.shutdownHandler(ctxTTL)
		}()

		select {
		case err := <-finished:
			if err != nil {
				done <- fmt.Errorf("graceful shutdown failed: %w", err)
			} else {
				logger.Info(ctx, "graceful shutdown successful")
				done <- nil
			}
		case <-ctxTTL.Done():
			done <- fmt.Errorf("graceful shutdown interrupted or deadline exceeded: %w", context.Cause(ctxTTL))
		}
	}()

	return done
}
