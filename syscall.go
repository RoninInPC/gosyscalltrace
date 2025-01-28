package gosyscalltrace

import (
	"fmt"
	"strings"
)

type Syscall struct {
	SyscallName    string
	PID            int
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
	enterWrite := fmt.Sprintf("tracepoint:syscalls:sys_enter_%s / pid!=%d / { printf(\"sys_enter_%s: %s %s\\n\",%s %s);}", s.SyscallName, s.PID, s.SyscallName, formatAnother, format, argsAnother, args)
	enterWrite = strings.Replace(enterWrite, ",  );}", ");}", -1)
	if s.GetRet {
		exitWrite := fmt.Sprintf("tracepoint:syscalls:sys_exit_%s / pid!=%d / { printf(\"sys_exit_%s: %s %s\\n\",%s %s);}", s.SyscallName, s.PID, s.SyscallName, formatAnother, "ret:%d", argsAnother, "args->ret")
		exitWrite = strings.Replace(exitWrite, ",  );}", ");}", -1)
		return fmt.Sprintf("%s\n%s\n", enterWrite, exitWrite)
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
