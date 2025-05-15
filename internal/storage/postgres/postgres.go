package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
	"github.com/sol1corejz/auth-service/internal/domain/models"
	"github.com/sol1corejz/auth-service/internal/storage"
	"os"
)

type Storage struct {
	db *sql.DB
}

func New() (*Storage, error) {
	const op = "storage.postgres.New"

	db, err := sql.Open("pgx", GetDatabaseURL())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &Storage{db: db}, nil
}

// SaveUser saves user to db and returns new user ID
func (s *Storage) SaveUser(ctx context.Context, email string, passHash []byte) (string, error) {
	const op = "storage.postgres.SaveUser"

	// Добавляем RETURNING id в запрос
	stmt, err := s.db.Prepare(`INSERT INTO users (email, pass_hash) VALUES ($1, $2) RETURNING user_id`)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close() // Важно закрывать statement

	var id uuid.UUID
	// Используем QueryRowContext с RETURNING
	err = stmt.QueryRowContext(ctx, email, passHash).Scan(&id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" {
				return "", fmt.Errorf("%s: %w", op, storage.ErrUserExists)
			}
		}
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return id.String(), nil
}

// User returns user by email.
func (s *Storage) User(ctx context.Context, email string) (models.User, error) {
	const op = "storage.postgres.User"

	stmt, err := s.db.Prepare("SELECT user_id, email, pass_hash FROM users WHERE email = $1")
	if err != nil {
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	row := stmt.QueryRowContext(ctx, email)

	var user models.User
	err = row.Scan(&user.ID, &user.Email, &user.PassHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}

		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	return user, nil
}

// IsAdmin return is user admin
func (s *Storage) IsAdmin(ctx context.Context, userID string) (bool, error) {
	const op = "storage.postgres.IsAdmin"

	stmt, err := s.db.Prepare("SELECT is_admin FROM users WHERE user_id = $1")
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	row := stmt.QueryRowContext(ctx, userID)
	var isAdmin bool
	err = row.Scan(&isAdmin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}

		return false, fmt.Errorf("%s: %w", op, err)
	}

	return isAdmin, nil
}

// App returns app by id.
func (s *Storage) App(ctx context.Context, name string) (models.App, error) {
	const op = "storage.postgres.App"

	stmt, err := s.db.Prepare("SELECT app_id, name FROM apps WHERE name = $1")
	if err != nil {
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}

	row := stmt.QueryRowContext(ctx, name)

	var app models.App
	err = row.Scan(&app.ID, &app.Name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.App{}, fmt.Errorf("%s: %w", op, storage.ErrAppNotFound)
		}

		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}

	return app, nil
}

func GetDatabaseURL() string {
	// Попробуем прочитать из переменных окружения (для Docker)
	dbURL := os.Getenv("DB_URL")
	if dbURL != "" {
		return dbURL
	}

	// Если не найдено в переменных окружения, пробуем .env (для локальной разработки)
	if err := godotenv.Load(); err == nil {
		dbURL = os.Getenv("DB_URL")
		if dbURL != "" {
			return dbURL
		}
	}

	panic("DB_URL not found in environment or .env file")
}
