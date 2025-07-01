package entity

import "time"

type Result struct {
	ID        int64
	PollID    int64
	OptionID  int64
	UserID    int64
	UserEmail *string
	VotedAt   time.Time
}
