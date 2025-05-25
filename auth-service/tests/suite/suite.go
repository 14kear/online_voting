// tests/suite/suite.go
package suite

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

// Suite – общая тестовая обвязка.
type Suite struct {
	*testing.T
	Cfg        *config.Config
	App        *app.App         // чтобы при желании дергать внутренние методы
	AuthClient ssov1.AuthClient // gRPC‑клиент для тестов
}

// New инициализирует приложение, поднимает gRPC‑сервер и возвращает gRPC‑клиента.
func New(t *testing.T) (context.Context, *Suite) {
	t.Helper()
	t.Parallel()

	// -------- 1. Загружаем конфиг --------------------
	cfg := config.Load("../config/local.yaml")

	// Заменяем порт на свободный (чтобы параллельные тесты не конфликтовали)
	cfg.GRPC.Port = freePort()

	// -------- 2. Стартуем приложение -----------------
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

	// -------- 3. Создаем gRPC‑клиент ------------------
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

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
		application.GRPCServer.Stop() // корректно глушим сервер после теста
	})

	return ctx, &Suite{
		T:          t,
		Cfg:        cfg,
		App:        application,
		AuthClient: ssov1.NewAuthClient(conn),
	}
}

// freePort выбирает свободный tcp‑порт (":0").
func freePort() int {
	l, _ := net.Listen("tcp", ":0")
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
