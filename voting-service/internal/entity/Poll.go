package entity

import "time"

type PollStatus string

const (
	PollStatusActive PollStatus = "active"
	PollStatusClosed PollStatus = "not-active"
)

type Poll struct {
	ID          int64
	Title       string
	Description string
	CreatorID   int64
	Status      PollStatus
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
