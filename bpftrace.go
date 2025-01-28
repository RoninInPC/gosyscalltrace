package gosyscalltrace

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
)

type Bpftrace struct {
	sync.RWMutex
	cmd           *exec.Cmd
	strChan       chan string
	endChan       chan bool
	traceInfoChan chan TraceInfo
	fileInput     string
	fileOutput    string
}

func NewBpftrace(fileInput, fileOutput string) *Bpftrace {
	return &Bpftrace{fileInput: fileInput, fileOutput: fileOutput}
}

func (b *Bpftrace) AddSyscall(syscall Syscall) {
	if !Exists(strings.TrimPrefix(syscall.SyscallName, "sys_enter_")) {
		panic(errors.New("Wrong syscallbpf name. Need Initialization for update syscalls or write true syscallbpf name."))
	}
	f, err := os.OpenFile(b.fileInput, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0777)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err = f.WriteString(syscall.ToBpftraceFormat()); err != nil {
		panic(err)
	}
}

func (b *Bpftrace) Trace() *exec.Cmd {
	b.Lock()
	defer b.Unlock()
	fp, err := os.Create(b.fileOutput)
	fp.Close()
	_ = os.Setenv("BPFTRACE_STRLEN", "128")
	b.cmd = exec.Command("bpftrace", b.fileInput)

	b.endChan = make(chan bool)
	b.strChan = make(chan string, 1000)
	b.traceInfoChan = make(chan TraceInfo, 1000)
	go b.cmd.Run()
	if err != nil {
		panic(err)
	}
	b.strChan, _ = b.asyncFileReader()
	go b.worker()
	return b.cmd
}

func (b *Bpftrace) asyncFileReader() (chan string, error) {
	channel := make(chan string)
	go func() {
		pipes, _ := b.cmd.StdoutPipe()
		scanner := bufio.NewScanner(pipes)
		for scanner.Scan() {
			line := scanner.Text()
			channel <- line
		}
	}()
	return channel, nil
}

func (b *Bpftrace) worker() {
	enter := ""
	for str := range b.strChan {
		if strings.HasPrefix(str, "Attaching") && strings.HasSuffix(str, "probes...\n") {
			continue
		}
		if strings.HasPrefix(str, "sys_exit_") {
			b.traceInfoChan <- StrFormatToTraceInfo(enter, str)
			enter = ""
		} else {
			if enter == "" {
				enter = str
			} else {
				b.traceInfoChan <- StrFormatToTraceInfo(enter, "")
				b.traceInfoChan <- StrFormatToTraceInfo(str, "")
				enter = ""
			}
		}
	}
}

func (b *Bpftrace) Events() <-chan TraceInfo {
	return b.traceInfoChan
}

func (b *Bpftrace) Stop() {
	b.endChan <- true
}
