package entity

import "time"

type Option struct {
	ID        int
	PollID    int
	Text      string
	CreatedAt time.Time
}
