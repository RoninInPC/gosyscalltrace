package gosyscalltrace

import (
	"strconv"
	"strings"
	"time"
)

type ArgInfo struct {
	Name  string
	Value string
}

type TraceInfo struct {
	SyscallName string
	PID         string
	UID         string
	Process     string
	Time        time.Time
	Ret         string
	Args        map[string]string
}

func StrFormatToTraceInfo(enter, exit string) TraceInfo {
	answer := TraceInfo{Time: time.Now()}

	args := make(map[string]string)
	if enter != "" {
		enter = strings.TrimSpace(enter)
		for _, splitted := range strings.Split(enter, " ") {
			parts := strings.Split(splitted, ":")

			if parts[0] == "" {
				continue
			}
			if strings.HasPrefix(parts[0], "sys_enter_") {
				answer.SyscallName = strings.TrimPrefix(parts[0], "sys_enter_")
				continue
			}
			if strings.HasPrefix(parts[0], "pid") {
				answer.PID = strings.Join(parts[1:], ":")
				continue
			}
			if strings.HasPrefix(parts[0], "uid") {
				answer.UID = strings.Join(parts[1:], ":")
				continue
			}
			if strings.HasPrefix(parts[0], "process") {
				answer.Process = strings.Join(parts[1:], ":")
				continue
			}
			if strings.HasPrefix(parts[0], "nanosec") {
				num, err := strconv.ParseInt(strings.Join(parts[1:], ":"), 10, 64)
				if err == nil {
					answer.Time = time.Unix(0, num)
				}
				continue
			}
			args[parts[0]] = strings.Join(parts[1:], ":")
		}
	}
	answer.Args = args
	if exit != "" {
		exit = strings.TrimSpace(exit)
		for _, splitted := range strings.Split(exit, " ") {
			parts := strings.Split(splitted, ":")
			if strings.HasPrefix(parts[0], "ret") {
				answer.Ret = strings.Join(parts[1:], ":")
			}
		}
	}
	return answer
}
