package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/14kear/online_voting/auth-service/internal/domain/models"
	"github.com/14kear/online_voting/auth-service/internal/storage"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
	"time"
)

type Storage struct {
	db *sql.DB
}

func New(postgresURL string) (*Storage, error) {
	const op = "storage.postgres.New"

	db, err := sql.Open("postgres", postgresURL)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	// Проверим соединение
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &Storage{db: db}, nil
}

func (s *Storage) SaveUser(ctx context.Context, email string, passHash []byte) (int64, error) {
	const op = "storage.postgres.SaveUser"

	stmt, err := s.db.Prepare("INSERT INTO users(email, pass_hash) VALUES($1, $2) RETURNING id")
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	var id int64
	err = stmt.QueryRowContext(ctx, email, passHash).Scan(&id)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return 0, fmt.Errorf("%s: %w", op, storage.ErrUserAlreadyExists)
		}
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

func (s *Storage) User(ctx context.Context, email string) (models.User, error) {
	const op = "storage.postgres.User"

	stmt, err := s.db.Prepare("SELECT id, email, pass_hash, is_blocked FROM users WHERE email = $1")
	if err != nil {
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	row := stmt.QueryRowContext(ctx, email)

	var user models.User
	err = row.Scan(&user.ID, &user.Email, &user.PassHash, &user.IsBlocked)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}
	return user, nil
}

func (s *Storage) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "storage.postgres.IsAdmin"

	stmt, err := s.db.Prepare("SELECT is_admin FROM users WHERE id = $1")
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

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

func (s *Storage) App(ctx context.Context, appID int) (models.App, error) {
	const op = "storage.postgres.App"

	stmt, err := s.db.Prepare("SELECT id, name, secret FROM apps WHERE id = $1")
	if err != nil {
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	row := stmt.QueryRowContext(ctx, appID)

	var app models.App
	err = row.Scan(&app.ID, &app.Name, &app.Secret)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.App{}, fmt.Errorf("%s: %w", op, storage.ErrAppNotFound)
		}
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}
	return app, nil
}

func (s *Storage) SaveToken(ctx context.Context, userID int64, appID int, token string, expiresAt time.Time) (int64, error) {
	const op = "storage.postgres.SaveToken"

	stmt, err := s.db.Prepare("INSERT INTO refresh_tokens(user_id, app_id, token, expires_at) VALUES($1, $2, $3, $4) RETURNING id")
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	var id int64
	err = stmt.QueryRowContext(ctx, userID, appID, token, expiresAt).Scan(&id)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" { // Код ошибки для уникальности
			return 0, fmt.Errorf("%s: token already exists for user %d and app %d: %w", op, userID, appID, storage.ErrTokenAlreadyExists)
		}
		return 0, fmt.Errorf("%s: failed to save refresh token: %w", op, err)
	}

	return id, nil
}

func (s *Storage) IsRefreshTokenValid(ctx context.Context, userID int64, appID int, token string) (bool, error) {
	const op = "storage.postgres.IsRefreshTokenValid"

	// TODO: передать время вместо now()
	stmt, err := s.db.Prepare(`
		SELECT EXISTS(
			SELECT 1 
			FROM refresh_tokens 
			WHERE token = $1 
			AND revoked = FALSE 
			AND expires_at > NOW() 
			AND user_id = $2 
			AND app_id = $3
		)`)

	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	var isValid bool
	err = stmt.QueryRowContext(ctx, token, userID, appID).Scan(&isValid)
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return isValid, nil
}

func (s *Storage) DeleteRefreshToken(ctx context.Context, userID int64, appID int, token string) error {
	const op = "storage.postgres.DeleteExpiredTokens"

	// TODO: передать время вместо now()
	stmt, err := s.db.Prepare("DELETE FROM refresh_tokens WHERE token = $1 AND user_id = $2 AND app_id = $3")
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	res, err := stmt.ExecContext(ctx, token, userID, appID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("%s: %w", op, storage.ErrTokenNotFound)
	}

	return nil
}

func (s *Storage) SetUserBlockStatus(ctx context.Context, userID int64, block bool) error {
	const op = "storage.postgres.SetUserBlockStatus"

	_, err := s.db.ExecContext(ctx, "UPDATE users SET is_blocked = $1 WHERE id = $2", block, userID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func (s *Storage) IsBlocked(ctx context.Context, userID int64) (bool, error) {
	query := `SELECT is_blocked FROM users WHERE id = $1`
	var isBlocked bool
	err := s.db.QueryRowContext(ctx, query, userID).Scan(&isBlocked)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, fmt.Errorf("IsBlocked: user not found")
		}
		return false, fmt.Errorf("IsBlocked: %w", err)
	}
	return isBlocked, nil
}

func (s *Storage) GetUsers(ctx context.Context) ([]models.User, error) {
	const op = "storage.postgres.GetUsers"

	rows, err := s.db.QueryContext(ctx, "SELECT id, email, is_blocked FROM users")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var user models.User
		err := rows.Scan(&user.ID, &user.Email, &user.IsBlocked)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return users, nil
}
