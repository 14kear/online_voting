package repo

import "errors"

var (
	ErrPollNotFound   = errors.New("poll not found")
	ErrOptionNotFound = errors.New("option not found")
	ErrResultNotFound = errors.New("result not found")
)
