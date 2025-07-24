package middleware

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/sgrumley/oauth/pkg/logger"
)

func LoggerMiddleware(next http.Handler, serviceName string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		log := logger.NewLogger()
		log.With(slog.String("service", fmt.Sprintf("[%s]", serviceName)))
		log.Logger = log.With(slog.String("service", fmt.Sprintf("[%s]", serviceName)))
		ctx = logger.AddLoggerContext(ctx, log.Logger)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
