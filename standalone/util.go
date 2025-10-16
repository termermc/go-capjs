package main

import "time"

func NowUnixHour() int64 {
	return time.Now().Unix() / 60 / 60
}
