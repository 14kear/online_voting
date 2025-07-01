package http

import (
	"context"
	"fmt"
	"github.com/14kear/online_voting/voting-service/internal/handlers"
	"github.com/14kear/online_voting/voting-service/internal/routes"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"log/slog"
	"net/http"
)

type App struct {
	engine *gin.Engine
	server *http.Server
	port   int
}

// NewApp инициализирует HTTP-сервер Gin и настраивает маршруты
func NewApp(
	port int,
	handler *handlers.VotingHandler,
	authMiddleware gin.HandlerFunc,
) *App {
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173", "http://localhost:4200"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "X-Refresh-Token"},
		ExposeHeaders:    []string{"X-New-Access-Token", "X-New-Refresh-Token"},
		AllowCredentials: true,
		AllowWebSockets:  true,
	}))

	// Группировка маршрутов: /api/voting/*
	api := r.Group("/api")
	{
		// Публичные маршруты
		publicForumGroup := api.Group("/voting")
		routes.RegisterPublicRoutes(publicForumGroup, handler)

		// Приватные маршруты (с авторизацией)
		privateForumGroup := api.Group("/voting", authMiddleware)
		routes.RegisterPrivateRoutes(privateForumGroup, handler)
	}

	// Healthcheck
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "pong"})
	})

	addr := fmt.Sprintf(":%d", port)
	httpServer := &http.Server{
		Addr:    addr,
		Handler: r,
	}

	return &App{
		engine: r,
		server: httpServer,
		port:   port,
	}
}

// Run запускает HTTP-сервер
func (a *App) Run() error {
	fmt.Println("HTTP server is running", slog.String("addr", a.server.Addr))
	return a.server.ListenAndServe()
}

// Stop корректно останавливает сервер
func (a *App) Stop(ctx context.Context) error {
	fmt.Println("HTTP server is stopping...")
	return a.server.Shutdown(ctx)
}

func (s *App) Engine() *gin.Engine {
	return s.engine
}
