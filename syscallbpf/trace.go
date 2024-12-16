package syscallbpf

import (
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
	Args        []ArgInfo
}

func StrFormatToTraceInfo(s string) TraceInfo {
	return TraceInfo{SyscallName: s}
}
