package main

import (
	"errors"
	"fmt"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/sol1corejz/auth-service/internal/storage/postgres"
	"log"
)

func main() {

	dbURL := postgres.GetDatabaseURL()
	fmt.Println(dbURL)

	// Создаем экземпляр мигратора
	m, err := migrate.New(
		"file://migrations",
		dbURL,
	)
	if err != nil {
		log.Fatalf("Failed to create migrate instance: %v", err)
	}
	defer m.Close()

	// Применяем миграции
	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			fmt.Println("Nothing to migrate")

			return
		}

		panic(err)
	}

	fmt.Println("Migrations applied successfully")
}
