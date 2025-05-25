package main

import (
	"context"
	"errors"
	"github.com/14kear/online_voting/voting-service/internal/app"
	"github.com/14kear/online_voting/voting-service/internal/config"
	"log"
	"log/slog"
	"net/http"
	_ "os"
	"os/signal"
	"syscall"
	"time"
)

const envLocal = "local"

func main() {
	cfg := config.Load("voting-service/config/local.yaml")

	application := app.NewApp(cfg.HTTP.Port, cfg.StoragePath, cfg.GRPC.Address)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := application.HTTPServer.Run(); err != nil {
			if errors.Is(err, http.ErrServerClosed) {
				log.Println("HTTP server closed gracefully")
			} else {
				log.Fatal("failed to run HTTP server", slog.String("error", err.Error()))
			}
		}
	}()

	log.Println("Forum service started", slog.String("env", envLocal), slog.Int("port", cfg.HTTP.Port))

	<-ctx.Done()

	log.Println("Shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := application.Stop(shutdownCtx); err != nil {
		log.Fatal("failed to stop application", slog.String("error", err.Error()))
	}
}
