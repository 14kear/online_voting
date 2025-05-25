package services

import (
	"context"
	"errors"
	"fmt"
	ssov1 "github.com/14kear/online_voting/protos/gen/go/auth"
	"github.com/14kear/online_voting/voting-service/internal/entity"
)

var ErrValidation = errors.New("validation error")

type OnlineVoting struct {
	logStorage    LogStorage
	optionStorage OptionStorage
	pollStorage   PollStorage
	resultStorage ResultStorage
	authService   ssov1.AuthClient
}

type LogStorage interface {
	SaveLog(ctx context.Context, log *entity.Log) (int64, error)
	GetLogs(ctx context.Context) ([]entity.Log, error)
}

type OptionStorage interface {
	SaveOption(ctx context.Context, pollID int64, text string) (int64, error)
	GetOptionsByPollID(ctx context.Context, pollID int64) ([]entity.Option, error)
	UpdateOption(ctx context.Context, id, pollID int64, text string) error
	DeleteOption(ctx context.Context, id, pollID int64) error
}

type PollStorage interface {
	SavePoll(ctx context.Context, title, description string, creatorID int64, status entity.PollStatus) (int64, error)
	GetPollByID(ctx context.Context, id int64) (entity.Poll, error)
	GetPolls(ctx context.Context) ([]entity.Poll, error)
	UpdatePoll(ctx context.Context, id int64, title, description string, status entity.PollStatus) error
	DeletePoll(ctx context.Context, id int64) error
}

type ResultStorage interface {
	SaveResult(ctx context.Context, pollID, optionID, userID int64) (int64, error)
	GetResultByID(ctx context.Context, id int64) (entity.Result, error)
	GetResultsByPollID(ctx context.Context, pollID int64) ([]entity.Result, error)
	GetResults(ctx context.Context) ([]entity.Result, error)
	DeleteResult(ctx context.Context, id int64) error
}

func NewOnlineVoting(
	logStorage LogStorage,
	optionStorage OptionStorage,
	pollStorage PollStorage,
	resultStorage ResultStorage,
	authService ssov1.AuthClient,
) *OnlineVoting {
	return &OnlineVoting{
		logStorage:    logStorage,
		optionStorage: optionStorage,
		pollStorage:   pollStorage,
		resultStorage: resultStorage,
		authService:   authService,
	}
}

func (v *OnlineVoting) CreatePoll(ctx context.Context, title, description string, creatorID int64, status entity.PollStatus) (int64, error) {
	const op = "OnlineVoting.CreatePoll"

	isAdminResp, err := v.authService.IsAdmin(ctx, &ssov1.IsAdminRequest{
		UserId: creatorID,
	})
	if err != nil {
		return 0, fmt.Errorf("%s: failed to check admin rights: %w", op, err)
	}

	if !isAdminResp.IsAdmin {
		return 0, fmt.Errorf("%s: user not authorized to create poll", op)
	}

	if title == "" || description == "" {
		return 0, fmt.Errorf("%w: title or description is empty", ErrValidation)
	}

	pollID, err := v.pollStorage.SavePoll(ctx, title, description, creatorID, status)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	log := &entity.Log{
		PollID: &pollID,
		UserID: creatorID,
		Action: op,
	}
	_, err = v.logStorage.SaveLog(ctx, log)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return pollID, nil
}

func (v *OnlineVoting) GetPollByID(ctx context.Context, id int64) (entity.Poll, error) {
	const op = "OnlineVoting.GetPollByID"

	poll, err := v.pollStorage.GetPollByID(ctx, id)
	if err != nil {
		return entity.Poll{}, fmt.Errorf("%s: %w", op, err)
	}

	return poll, nil
}

func (v *OnlineVoting) GetPolls(ctx context.Context) ([]entity.Poll, error) {
	const op = "OnlineVoting.GetPolls"

	polls, err := v.pollStorage.GetPolls(ctx)
	if err != nil {
		return []entity.Poll{}, fmt.Errorf("%s: %w", op, err)
	}

	return polls, nil
}

func (v *OnlineVoting) UpdatePoll(ctx context.Context, id int64, title, description string, status entity.PollStatus, userID int64) error {
	const op = "OnlineVoting.UpdatePoll"

	isAdminResp, err := v.authService.IsAdmin(ctx, &ssov1.IsAdminRequest{
		UserId: userID,
	})
	if err != nil {
		return fmt.Errorf("%s: failed to check admin rights: %w", op, err)
	}

	if !isAdminResp.IsAdmin {
		return fmt.Errorf("%s: user not authorized to update this poll", op)
	}

	err = v.pollStorage.UpdatePoll(ctx, id, title, description, status)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	log := &entity.Log{
		PollID: &id,
		Action: op,
		UserID: userID,
	}

	_, err = v.logStorage.SaveLog(ctx, log)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (v *OnlineVoting) DeletePoll(ctx context.Context, id int64, userID int64) error {
	const op = "OnlineVoting.DeletePoll"

	isAdminResp, err := v.authService.IsAdmin(ctx, &ssov1.IsAdminRequest{
		UserId: userID,
	})
	if err != nil {
		return fmt.Errorf("%s: failed to check admin rights: %w", op, err)
	}

	if !isAdminResp.IsAdmin {
		return fmt.Errorf("%s: user not authorized to delete this poll", op)
	}

	err = v.pollStorage.DeletePoll(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	log := &entity.Log{
		PollID: &id,
		UserID: userID,
		Action: op,
	}

	_, err = v.logStorage.SaveLog(ctx, log)

	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (v *OnlineVoting) CreateOption(ctx context.Context, pollID int64, text string, userID int64) (int64, error) {
	const op = "OnlineVoting.CreateOption"

	isAdminResp, err := v.authService.IsAdmin(ctx, &ssov1.IsAdminRequest{
		UserId: userID,
	})

	if err != nil {
		return 0, fmt.Errorf("%s: failed to check admin rights: %w", op, err)
	}

	if !isAdminResp.IsAdmin {
		return 0, fmt.Errorf("%s: user not authorized to create this option", op)
	}

	optionID, err := v.optionStorage.SaveOption(ctx, pollID, text)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	log := &entity.Log{
		PollID:   &pollID,
		UserID:   userID,
		Action:   op,
		OptionID: &optionID,
	}

	_, err = v.logStorage.SaveLog(ctx, log)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return optionID, nil
}

func (v *OnlineVoting) GetOptionsByPollID(ctx context.Context, pollID int64) ([]entity.Option, error) {
	const op = "OnlineVoting.GetOptionsByPollID"

	options, err := v.optionStorage.GetOptionsByPollID(ctx, pollID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return options, nil
}

func (v *OnlineVoting) UpdateOption(ctx context.Context, id, pollID int64, text string, userID int64) error {
	const op = "OnlineVoting.UpdateOption"

	isAdminResp, err := v.authService.IsAdmin(ctx, &ssov1.IsAdminRequest{
		UserId: userID,
	})

	if err != nil {
		return fmt.Errorf("%s: failed to check admin rights: %w", op, err)
	}

	if !isAdminResp.IsAdmin {
		return fmt.Errorf("%s: user not authorized to update this option", op)
	}

	err = v.optionStorage.UpdateOption(ctx, id, pollID, text)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	log := &entity.Log{
		OptionID: &id,
		Action:   op,
		UserID:   userID,
		PollID:   &pollID,
	}

	_, err = v.logStorage.SaveLog(ctx, log)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (v *OnlineVoting) DeleteOption(ctx context.Context, id, pollID int64, userID int64) error {
	const op = "OnlineVoting.DeleteOption"

	isAdminResp, err := v.authService.IsAdmin(ctx, &ssov1.IsAdminRequest{
		UserId: userID,
	})

	if err != nil {
		return fmt.Errorf("%s: failed to check admin rights: %w", op, err)
	}

	if !isAdminResp.IsAdmin {
		return fmt.Errorf("%s: user not authorized to delete this option", op)
	}

	err = v.optionStorage.DeleteOption(ctx, id, pollID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	log := &entity.Log{
		OptionID: &id,
		Action:   op,
		UserID:   userID,
		PollID:   &pollID,
	}

	_, err = v.logStorage.SaveLog(ctx, log)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (v *OnlineVoting) SaveResult(ctx context.Context, pollID, optionID, userID int64) (int64, error) {
	const op = "OnlineVoting.SaveResult"

	resultID, err := v.resultStorage.SaveResult(ctx, pollID, optionID, userID)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	log := &entity.Log{
		PollID:   &pollID,
		Action:   op,
		UserID:   userID,
		OptionID: &optionID,
		ResultID: &resultID,
	}

	_, err = v.logStorage.SaveLog(ctx, log)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return resultID, nil
}

func (v *OnlineVoting) GetResultByID(ctx context.Context, id int64) (entity.Result, error) {
	const op = "OnlineVoting.GetResultByID"

	result, err := v.resultStorage.GetResultByID(ctx, id)
	if err != nil {
		return entity.Result{}, fmt.Errorf("%s: %w", op, err)
	}

	return result, nil
}

func (v *OnlineVoting) GetResultsByPollID(ctx context.Context, pollID int64) ([]entity.Result, error) {
	const op = "OnlineVoting.GetResultsByPollID"

	result, err := v.resultStorage.GetResultsByPollID(ctx, pollID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return result, nil
}

func (v *OnlineVoting) GetResults(ctx context.Context) ([]entity.Result, error) {
	const op = "OnlineVoting.GetResults"

	results, err := v.resultStorage.GetResults(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return results, nil
}

func (v *OnlineVoting) DeleteResult(ctx context.Context, id int64, userID int64) error {
	const op = "OnlineVoting.DeleteResult"

	isAdminResp, err := v.authService.IsAdmin(ctx, &ssov1.IsAdminRequest{
		UserId: userID,
	})

	if err != nil {
		return fmt.Errorf("%s: failed to check admin rights: %w", op, err)
	}

	if !isAdminResp.IsAdmin {
		return fmt.Errorf("%s: user not authorized to delete this result", op)
	}

	dataResult, err := v.resultStorage.GetResultByID(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	log := &entity.Log{
		Action:   op,
		UserID:   userID,
		ResultID: &id,
		PollID:   &dataResult.PollID,
		OptionID: &dataResult.OptionID,
	}

	_, err = v.logStorage.SaveLog(ctx, log)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	err = v.resultStorage.DeleteResult(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (v *OnlineVoting) GetLogs(ctx context.Context) ([]entity.Log, error) {
	const op = "OnlineVoting.GetLogs"

	logs, err := v.logStorage.GetLogs(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return logs, nil
}
