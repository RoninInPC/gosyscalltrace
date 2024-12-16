package syscall

import (
	"bufio"
	"errors"
	"fmt"
	"gosyscalltrace/syscallsenter"
	"os"
	"os/exec"
	"strings"
)

type Bpftrace struct {
	fileInput  string
	fileOutput string
}

func NewBpftrace(fileInput, fileOutput string) *Bpftrace {
	return &Bpftrace{fileInput: fileInput, fileOutput: fileOutput}
}

func (b *Bpftrace) AddSyscall(syscall Syscall) {
	if syscallsenter.Exists(strings.TrimPrefix(syscall.SyscallName, "sys_enter_")) {
		panic(errors.New("Wrong syscall name. Need Initialization for update syscalls or write true syscall name."))
	}
	os.WriteFile(b.fileInput, []byte(syscall.ToBpftraceFormat()), 777)
}

func (b Bpftrace) Trace() (chan TraceInfo, *exec.Cmd) {
	fp, _ := os.Open(b.fileOutput)
	cmd := exec.Command(fmt.Sprintf("bpftrace -o %s %s", b.fileOutput, b.fileInput))
	answer := make(chan TraceInfo)
	cmd.Run()
	go func() {
		defer fp.Close()
		defer close(answer)

		scanner := bufio.NewScanner(fp)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			answer <- StrFormatToTraceInfo(scanner.Text())
		}
	}()
	return answer, cmd
}
