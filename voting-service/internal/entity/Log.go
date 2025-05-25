package entity

import "time"

type Log struct {
	ID        int64
	UserID    int64
	Action    string
	PollID    int64
	OptionID  int64
	CreatedAt time.Time
}
