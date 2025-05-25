package app

import (
	grpcapp "github.com/14kear/online_voting/auth-service/internal/app/grpc"
	"github.com/14kear/online_voting/auth-service/internal/services/auth"
	"github.com/14kear/online_voting/auth-service/internal/storage/postgres"
	"log/slog"
	"time"
)

type App struct {
	GRPCServer *grpcapp.App
}

func NewApp(log *slog.Logger, grpcPort int, storagePath string, accessTokenTTL time.Duration, refreshTokenTTL time.Duration) *App {
	storage, err := postgres.New(storagePath)
	if err != nil {
		panic(err)
	}

	authService := auth.NewAuth(log, storage, storage, storage, storage, accessTokenTTL, refreshTokenTTL)

	grpcApp := grpcapp.NewApp(log, authService, grpcPort)

	return &App{
		GRPCServer: grpcApp,
	}
}
