package entity

import "time"

type Poll struct {
	ID          int
	Title       string
	Description string
	CreatorID   int64
	Status      string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
