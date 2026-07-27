package aauth

import "time"

// Clock supplies protocol time without imposing a process-global clock.
type Clock interface {
	Now() time.Time
}

// ClockFunc adapts a function to Clock.
type ClockFunc func() time.Time

func (clock ClockFunc) Now() time.Time {
	return clock()
}

// SystemClock uses the current system time.
type SystemClock struct{}

func (SystemClock) Now() time.Time {
	return time.Now()
}
