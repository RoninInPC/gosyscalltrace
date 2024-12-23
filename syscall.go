package gosyscalltrace

import (
	"fmt"
	"strings"
)

type Syscall struct {
	SyscallName    string
	Args           Args
	GetTime        bool
	GetPID         bool
	GetUID         bool
	GetProcessName bool
	GetRet         bool
}

// { printf("%s %d %d %s %s %d %d\n",
// strftime("%y.%m.%d %H:%M:%S", nsecs),
// uid, pid, comm, str(args->filename), args->flags, args->mode); }
//
//tracepoint:syscalls:sys_enter_openat
func (s Syscall) ToBpftraceFormat() string {
	format, args := s.Args.ToBpftraceFormat()
	formatAnother, argsAnother := s.toBpftraceAnotherArgsFormat()
	s.SyscallName = strings.TrimPrefix(s.SyscallName, "sys_enter_")
	enterWrite := fmt.Sprintf("tracepoint:syscalls:sys_enter_%s{ printf(\"sys_enter_%s: %s %s\\n\",%s %s);}", s.SyscallName, s.SyscallName, formatAnother, format, argsAnother, args)
	if s.GetRet {
		exitWite := fmt.Sprintf("tracepoint:syscalls:sys_exit_%s{ printf(\"sys_exit_%s: %s %s\\n\",%s %s);}", s.SyscallName, s.SyscallName, formatAnother, "ret:%d", argsAnother, "args->ret")
		return fmt.Sprintf("%s\n%s", enterWrite, exitWite)
	}
	return enterWrite + "\n"
}

func (s Syscall) toBpftraceAnotherArgsFormat() (string, string) {
	format := ""
	args := ""
	if s.GetTime {
		format += "nanosec:%llu "
		args += "nsecs, "
	}
	if s.GetPID {
		format += "pid:%d "
		args += "pid, "
	}
	if s.GetUID {
		format += "uid:%d "
		args += "uid, "
	}
	if s.GetProcessName {
		format += "process_name:%s "
		args += "comm, "
	}
	return format, args
}
