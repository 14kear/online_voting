package entity

import "time"

type Option struct {
	ID        int64
	PollID    int64
	Text      string
	CreatedAt time.Time
}
