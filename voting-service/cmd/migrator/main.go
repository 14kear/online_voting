package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/golang-migrate/migrate/v4"

	// Подключаем PostgreSQL драйвер
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	// Подключаем файловый источник миграций
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func main() {
	var dbURL, migrationsPath, migrationsTable string

	flag.StringVar(&dbURL, "db-url", "", "PostgreSQL connection string")
	flag.StringVar(&migrationsPath, "migrations-path", "", "Path to migrations")
	flag.StringVar(&migrationsTable, "migrations-table", "schema_migrations", "Name of the migrations table (optional)")
	flag.Parse()

	if dbURL == "" {
		panic("db-url is required")
	}
	if migrationsPath == "" {
		panic("migrations-path is required")
	}

	// Добавляем параметр x-migrations-table, если задано
	if migrationsTable != "" {
		if dbURL[len(dbURL)-1] != '?' && dbURL[len(dbURL)-1] != '&' {
			if !containsQueryParams(dbURL) {
				dbURL += "?"
			} else {
				dbURL += "&"
			}
		}
		dbURL += "x-migrations-table=" + migrationsTable
	}

	m, err := migrate.New(
		"file://"+migrationsPath,
		dbURL,
	)
	if err != nil {
		panic(fmt.Errorf("failed to create migrate instance: %w", err))
	}

	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			fmt.Println("Nothing to migrate")
			return
		}
		panic(fmt.Errorf("migration failed: %w", err))
	}

	fmt.Println("Migrations applied successfully")
}

// containsQueryParams checks if URL already has '?'
func containsQueryParams(s string) bool {
	for _, c := range s {
		if c == '?' {
			return true
		}
	}
	return false
}
