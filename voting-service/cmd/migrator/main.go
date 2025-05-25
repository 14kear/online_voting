package main

import (
	"database/sql"
	"flag"
	"fmt"
	"github.com/14kear/onlineVotingBackend/voting-service/internal/config"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"log"
)

func main() {
	var (
		action     string
		steps      int
		configPath string
	)

	flag.StringVar(&action, "action", "up", "Миграция: up, down, force, version")
	flag.IntVar(&steps, "steps", 0, "Количество шагов (для up/down)")
	flag.StringVar(&configPath, "config", "voting-service/config/local.yaml",
		"Путь к конфигурационному файлу")
	flag.Parse()

	cfg, err := config.LoadConfig(configPath)

	db, err := sql.Open("postgres", cfg.Database.GetConnectionString())
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		log.Fatal(err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://C:/Users/Egor/Desktop/online_voting/voting-service/migrations",
		"postgres", driver,
	)
	if err != nil {
		log.Fatal(err)
	}

	switch action {
	case "up":
		if steps > 0 {
			err = m.Steps(steps)
		} else {
			err = m.Up()
		}
	case "down":
		if steps > 0 {
			err = m.Steps(-steps)
		} else {
			err = m.Down()
		}
	case "force":
		err = m.Force(steps)
	case "version":
		version, dirty, err := m.Version()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Version: %d, Dirty: %v\n\n", version, dirty)
		return
	default:
		log.Fatalf("Неизвестное действие: %s", action)
	}

	if err != nil && err != migrate.ErrNoChange {
		log.Fatal(err)
	}

	fmt.Println("Миграция успешно выполнена")
}
