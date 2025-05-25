package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/14kear/online_voting/voting-service/internal/entity"
	"github.com/14kear/online_voting/voting-service/internal/repo"
	_ "github.com/lib/pq"
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

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &Storage{db: db}, nil
}

func (s *Storage) SavePoll(ctx context.Context, title, description string, creatorID int64, status entity.PollStatus) (int64, error) {
	const op = "storage.postgres.NewPoll"

	query := `INSERT INTO polls (title, description, creator_id, status) VALUES ($1, $2, $3, $4) RETURNING id`

	var id int64
	err := s.db.QueryRowContext(ctx, query, title, description, creatorID, status).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

func (s *Storage) GetPollByID(ctx context.Context, id int64) (entity.Poll, error) {
	const op = "storage.postgres.GetPollByID"

	query := `SELECT id, title, description, creator_id, status, created_at, updated_at FROM polls WHERE id = $1`

	var poll entity.Poll
	err := s.db.QueryRowContext(ctx, query, id).Scan(&poll.ID, &poll.Title, &poll.Description, &poll.CreatorID, &poll.Status, &poll.CreatedAt, &poll.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return entity.Poll{}, fmt.Errorf("%s: %w", op, repo.ErrPollNotFound)
		}
		return entity.Poll{}, fmt.Errorf("%s: %w", op, err)
	}

	return poll, nil
}

func (s *Storage) GetPolls(ctx context.Context) ([]entity.Poll, error) {
	const op = "storage.postgres.GetPolls"

	query := `SELECT id, title, description, creator_id, status, created_at, updated_at FROM polls ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()

	var polls []entity.Poll
	for rows.Next() {
		var poll entity.Poll
		if err := rows.Scan(&poll.ID, &poll.Title, &poll.Description, &poll.CreatorID, &poll.Status, &poll.CreatedAt, &poll.UpdatedAt); err != nil {
			return nil, fmt.Errorf("%s: scan: %w", op, err)
		}
		polls = append(polls, poll)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: rows error: %w", op, err)
	}

	return polls, nil
}

func (s *Storage) UpdatePoll(ctx context.Context, id int64, title, description string, status entity.PollStatus) error {
	const op = "storage.postgres.UpdatePoll"

	const query = `UPDATE polls SET title = $1, description = $2, status = $3, updated_at  = NOW() WHERE  id = $4`

	res, err := s.db.ExecContext(ctx, query, title, description, status, id)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%s: %w", op, repo.ErrPollNotFound)
	}
	return nil
}

func (s *Storage) DeletePoll(ctx context.Context, id int64) error {
	const op = "storage.postgres.DeletePoll"

	query := `DELETE FROM polls WHERE id = $1`

	res, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if n, _ := res.RowsAffected(); n == 0 {
		return repo.ErrPollNotFound
	}

	return nil
}

func (s *Storage) SaveOption(ctx context.Context, pollID int64, text string) (int64, error) {
	const op = "storage.postgres.SaveOption"

	query := `INSERT INTO options (poll_id, text) VALUES ($1, $2) RETURNING id`

	var id int64
	err := s.db.QueryRowContext(ctx, query, pollID, text).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, repo.ErrOptionNotFound)
	}

	return id, nil
}

func (s *Storage) GetOptionsByPollID(ctx context.Context, pollID int64) ([]entity.Option, error) {
	const op = "storage.postgres.GetOptionsByPollID"

	query := `SELECT id, poll_id, text, created_at FROM options WHERE poll_id = $1 ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query, pollID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()

	var options []entity.Option
	for rows.Next() {
		var option entity.Option
		if err := rows.Scan(&option.ID, &option.PollID, &option.Text, &option.CreatedAt); err != nil {
			return nil, fmt.Errorf("%s: scan: %w", op, err)
		}
		options = append(options, option)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: rows error: %w", op, err)
	}

	return options, nil
}

func (s *Storage) UpdateOption(ctx context.Context, id, pollID int64, text string) error {
	const op = "storage.postgres.UpdateOption"

	const query = `UPDATE options SET text = $1 WHERE id = $2 AND poll_id = $3`

	res, err := s.db.ExecContext(ctx, query, text, id, pollID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%s: %w", op, repo.ErrOptionNotFound)
	}
	return nil

}

func (s *Storage) DeleteOption(ctx context.Context, id int64, pollID int64) error {
	const op = "storage.postgres.DeleteOption"

	query := `DELETE FROM options WHERE id = $1 AND poll_id = $2`

	res, err := s.db.ExecContext(ctx, query, id, pollID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if n, _ := res.RowsAffected(); n == 0 {
		return repo.ErrOptionNotFound
	}

	return nil
}

func (s *Storage) SaveResult(ctx context.Context, pollID, optionID, userID int64) (int64, error) {
	const op = "storage.postgres.SaveResult"

	query := `INSERT INTO results (poll_id, option_id, user_id) VALUES ($1, $2, $3) RETURNING id`

	var id int64
	err := s.db.QueryRowContext(ctx, query, pollID, optionID, userID).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

func (s *Storage) GetResultByID(ctx context.Context, id int64) (entity.Result, error) {
	const op = "storage.postgres.GetResultByID"

	query := `SELECT id, poll_id, option_id, user_id, voted_at FROM results WHERE id = $1 ORDER BY voted_at DESC`

	var result entity.Result
	err := s.db.QueryRowContext(ctx, query, id).Scan(&result.ID, &result.PollID, &result.OptionID, &result.UserID, &result.VotedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return entity.Result{}, repo.ErrResultNotFound
		}
		return entity.Result{}, fmt.Errorf("%s: %w", op, err)
	}

	return result, nil
}

func (s *Storage) GetResultsByPollID(ctx context.Context, pollID int64) ([]entity.Result, error) {
	const op = "storage.postgres.GetResultsByPollID"

	query := `SELECT id, poll_id, option_id, user_id, voted_at FROM results WHERE poll_id = $1 ORDER BY voted_at DESC`

	rows, err := s.db.QueryContext(ctx, query, pollID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()

	var results []entity.Result
	for rows.Next() {
		var result entity.Result
		if err := rows.Scan(&result.ID, &result.PollID, &result.OptionID, &result.UserID, &result.VotedAt); err != nil {
			return nil, fmt.Errorf("%s: scan: %w", op, err)
		}
		results = append(results, result)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: rows error: %w", op, err)
	}

	return results, nil
}

func (s *Storage) GetResults(ctx context.Context) ([]entity.Result, error) {
	const op = "storage.postgres.GetResults"

	query := `SELECT id, poll_id, option_id, user_id, voted_at FROM results ORDER BY voted_at DESC`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()

	var results []entity.Result
	for rows.Next() {
		var result entity.Result
		if err := rows.Scan(&result.ID, &result.PollID, &result.OptionID, &result.UserID, &result.VotedAt); err != nil {
			return nil, fmt.Errorf("%s: scan: %w", op, err)
		}
		results = append(results, result)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: rows error: %w", op, err)
	}

	return results, nil
}

func (s *Storage) DeleteResult(ctx context.Context, id int64) error {
	const op = "storage.postgres.DeleteResult"

	query := `DELETE FROM results WHERE id = $1`

	res, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if n, _ := res.RowsAffected(); n == 0 {
		return repo.ErrResultNotFound
	}

	return nil
}

func (s *Storage) SaveLog(ctx context.Context, log *entity.Log) (int64, error) {
	const op = "storage.postgres.SaveLog"

	query := `INSERT INTO logs (user_id, action, poll_id, option_id, result_id) VALUES ($1, $2, $3, $4, $5) RETURNING id`

	err := s.db.QueryRowContext(ctx, query, log.UserID, log.Action, log.PollID, log.OptionID, log.ResultID).Scan(&log.ID)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return log.ID, nil
}

func (s *Storage) GetLogs(ctx context.Context) ([]entity.Log, error) {
	const op = "storage.postgres.GetLogs"

	query := `SELECT id, user_id, action, poll_id, option_id, result_id, created_at FROM logs ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()

	var logs []entity.Log
	for rows.Next() {
		var log entity.Log
		if err := rows.Scan(&log.ID, &log.UserID, &log.Action, &log.PollID, &log.OptionID, &log.ResultID, &log.CreatedAt); err != nil {
			return nil, fmt.Errorf("%s: scan: %w", op, err)
		}
		logs = append(logs, log)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: rows error: %w", op, err)
	}

	return logs, nil
}
