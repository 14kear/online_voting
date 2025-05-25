package entity

import "time"

type Result struct {
	ID       int
	PollID   int
	OptionID int
	UserID   int64
	VotedAt  time.Time
}
