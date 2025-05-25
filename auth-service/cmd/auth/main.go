package main

import (
	"context"
	"errors"
	"github.com/14kear/online_voting/auth-service/internal/app"
	"github.com/14kear/online_voting/auth-service/internal/config"
	"github.com/14kear/online_voting/auth-service/utils"
	gw "github.com/14kear/online_voting/protos/gen/go/auth"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/rs/cors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

const (
	envLocal = "local"
	// envProd  = "prod"
	envDev = "dev"
)

func main() {
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:5173"}, // Разрешаем доступ с фронта на localhost:3000
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	})

	cfg := config.Load("auth-service/config/local.yaml")

	log := utils.New(cfg.Env)

	if cfg.Env == envLocal || cfg.Env == envDev {
		log.Info("Starting auth service", slog.Any("config", cfg))
	} else {
		log.Info("Starting auth service")
	}

	application := app.NewApp(log, cfg.GRPC.Port, cfg.StoragePath, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)

	go func() {
		err := application.GRPCServer.Run()
		if err != nil {
			log.Error("Failed to start auth service", slog.Any("error", err))
		}
	}()

	// Start HTTP gateway
	gatewayCtx, gatewayCancel := context.WithCancel(context.Background())
	defer gatewayCancel()

	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}

	grpcAddress := "localhost:" + strconv.Itoa(cfg.GRPC.Port)
	if err := gw.RegisterAuthHandlerFromEndpoint(gatewayCtx, mux, grpcAddress, opts); err != nil {
		log.Error("Failed to register auth handler", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// HTTP сервер с поддержкой CORS
	handler := c.Handler(mux)

	gatewayServer := &http.Server{
		Addr:    ":" + strconv.Itoa(cfg.HTTP.Port),
		Handler: handler,
	}

	go func() {
		log.Info("Starting HTTP gateway", slog.String("port", strconv.Itoa(cfg.HTTP.Port)))
		err := gatewayServer.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("Failed to start gateway", slog.String("error", err.Error()))
		} else if errors.Is(err, http.ErrServerClosed) {
			log.Info("HTTP Gateway server shutdown", slog.String("port", strconv.Itoa(cfg.HTTP.Port)))
		}
	}()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	select {
	case signl := <-stop:
		log.Info("Shutting down auth service", slog.String("signal", signl.String()))
	}

	// Shutdown procedures
	gatewayCancel()
	if err := gatewayServer.Shutdown(context.Background()); err != nil {
		log.Error("Failed to shutdown HTTP gateway", slog.String("error", err.Error()))
	}

	application.GRPCServer.Stop()
	log.Info("Application stopped")
}
