package web

import (
	"context"
	"net/http"
	"os"
	"syscall"
	"time"
)

type (
	HandleExitOption func(c *exitConfig)
	ShutdownHandler  func(context.Context) error
)

type exitConfig struct {
	ctx             context.Context
	timeout         time.Duration
	trappedSignals  []os.Signal
	shutdownHandler func(context.Context) error
	server          *http.Server
}

func WithTimeout(timeout time.Duration) HandleExitOption {
	return func(c *exitConfig) {
		c.timeout = timeout
	}
}

func WithCTX(ctx context.Context) HandleExitOption {
	return func(c *exitConfig) {
		c.ctx = ctx
	}
}

func WithTrappedSignals(signals []os.Signal) HandleExitOption {
	return func(c *exitConfig) {
		c.trappedSignals = signals
	}
}

func WithShutDownHandler(fn ShutdownHandler) HandleExitOption {
	return func(c *exitConfig) {
		c.shutdownHandler = fn
	}
}

func defaultShutdownHandler(server *http.Server) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		if err := server.Shutdown(ctx); err != nil {
			return err
		}
		return nil
	}
}

func newConfig(server *http.Server, opts ...HandleExitOption) *exitConfig {
	cfg := &exitConfig{
		ctx:     context.Background(),
		server:  server,
		timeout: time.Second * 30,
		trappedSignals: []os.Signal{
			os.Interrupt,
			syscall.SIGTERM,
		},
		shutdownHandler: defaultShutdownHandler(server),
	}

	for _, fn := range opts {
		fn(cfg)
	}

	return cfg
}
