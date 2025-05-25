package utils

import (
	"github.com/14kear/sso-prettyslog/slogpretty/slogpretty"
	"log/slog"
	"os"
)

const (
	EnvLocal = "local"
)

func New(env string) *slog.Logger {
	switch env {
	case EnvLocal:
		return newPretty()
	default:
		return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
}

func newPretty() *slog.Logger {
	opts := slogpretty.PrettyHandlerOptions{
		SlogOpts: &slog.HandlerOptions{
			Level: slog.LevelDebug,
		},
	}
	return slog.New(opts.NewPrettyHandler(os.Stdout))
}
