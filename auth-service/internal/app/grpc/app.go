package grpcapp

import (
	"fmt"
	authgrpc "github.com/14kear/onlineVotingBackend/auth-service/internal/grpc/auth"
	"google.golang.org/grpc"
	"log/slog"
	"net"
)

type App struct {
	log        *slog.Logger
	gRPCServer *grpc.Server
	port       int
}

func NewApp(log *slog.Logger, authService authgrpc.Auth, port int) *App {
	//gRPCServer := grpc.NewServer(grpc.ChainUnaryInterceptor(authInterceptor(authService)))
	gRPCServer := grpc.NewServer()

	authgrpc.Register(gRPCServer, authService)
	return &App{
		log:        log,
		gRPCServer: gRPCServer,
		port:       port,
	}
}

func (a *App) Run() error {
	const op = "grpcapp.Run"

	log := a.log.With(slog.String("op", op), slog.Int("port", a.port))

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", a.port))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("gRPC server is running", slog.String("addr", lis.Addr().String()))

	if err := a.gRPCServer.Serve(lis); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (a *App) Stop() {
	const op = "grpcapp.Stop"

	a.log.With(slog.String("op", op)).Info("gRPC server is stopping")
	a.gRPCServer.GracefulStop() // блокирует выполнение кода пока не обработаются текущие соединения
}
