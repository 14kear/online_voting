package app

import (
	"context"
	httpapp "github.com/14kear/online_voting/voting-service/internal/app/http"
	"github.com/14kear/online_voting/voting-service/internal/grpcclient"
	"github.com/14kear/online_voting/voting-service/internal/handlers"
	"github.com/14kear/online_voting/voting-service/internal/middleware"
	"github.com/14kear/online_voting/voting-service/internal/repo/postgres"
	"github.com/14kear/online_voting/voting-service/internal/services"
	"google.golang.org/grpc"
)

type App struct {
	HTTPServer *httpapp.App
	Voting     *services.OnlineVoting
	conn       *grpc.ClientConn
}

func NewApp(httpPort int, storagePath string, authGRPCAddr string) *App {
	storage, err := postgres.New(storagePath)
	if err != nil {
		panic(err)
	}

	// gRPC client to auth-service
	conn, err := grpc.Dial(authGRPCAddr, grpc.WithInsecure())
	if err != nil {
		panic(err)
	}

	authClient := grpcclient.NewClient(conn)
	authMiddleware := middleware.NewAuthMiddleware(authClient.AuthClient, 1)

	votingService := services.NewOnlineVoting(storage, storage, storage, storage, authClient.AuthClient)
	votingServer := handlers.NewVotingHandler(votingService)

	httpApp := httpapp.NewApp(httpPort, votingServer, authMiddleware.Middleware())

	app := &App{
		HTTPServer: httpApp,
		Voting:     votingService,
		conn:       conn,
	}

	return app
}

func (a *App) Stop(ctx context.Context) error {
	if err := a.HTTPServer.Stop(ctx); err != nil {
		return err
	}
	return a.conn.Close()
}
