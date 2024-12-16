package main

import (
	"fmt"
	"gosyscalltrace/syscallbpf"
)

func main() {
	bpftrace := syscallbpf.NewBpftrace("input.txt", "output.txt")
	bpftrace.AddSyscall(syscallbpf.Syscall{
		SyscallName:    "sys_enter_openat",
		GetRet:         true,
		GetTime:        true,
		GetPID:         true,
		GetUID:         true,
		GetProcessName: true,
		Args: syscallbpf.Args{
			{syscallbpf.S, "filename", true}}})
	bpftrace.Trace()
	for c := range bpftrace.Events() {
		fmt.Println(c.SyscallName)
	}
}
