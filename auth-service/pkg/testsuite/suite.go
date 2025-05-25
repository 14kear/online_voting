package testsuite

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/14kear/onlineVotingBackend/auth-service/internal/app"
	"github.com/14kear/onlineVotingBackend/auth-service/internal/config"
	"github.com/14kear/onlineVotingBackend/auth-service/utils"

	ssov1 "github.com/14kear/forum-project/protos/gen/go/auth"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Suite — структура для тестов auth-service (экспортируемая)
type Suite struct {
	AuthClient ssov1.AuthClient
	Cfg        *config.Config
	App        *app.App
	ctx        context.Context
	Cancel     context.CancelFunc
	GRPCaddr   string
}

func New(t *testing.T) *Suite {
	t.Helper()

	cfg := config.Load("C:\\Users\\shini\\OneDrive\\Рабочий стол\\forum-project\\auth-service\\config\\local.yaml")
	cfg.GRPC.Port = freePort()

	log := utils.New(cfg.Env)
	application := app.NewApp(
		log,
		cfg.GRPC.Port,
		cfg.StoragePath,
		cfg.AccessTokenTTL,
		cfg.RefreshTokenTTL,
	)

	go func() {
		if err := application.GRPCServer.Run(); err != nil {
			t.Fatalf("gRPC server failed: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	addr := net.JoinHostPort("localhost", strconv.Itoa(cfg.GRPC.Port))
	conn, err := grpc.DialContext(
		ctx,
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("dial gRPC: %v", err)
	}

	t.Cleanup(func() {
		conn.Close()
		application.GRPCServer.Stop()
		cancel()
	})

	return &Suite{
		AuthClient: ssov1.NewAuthClient(conn),
		Cfg:        cfg,
		App:        application,
		ctx:        ctx,
		Cancel:     cancel,
		GRPCaddr:   addr,
	}
}

func freePort() int {
	l, _ := net.Listen("tcp", ":0")
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
