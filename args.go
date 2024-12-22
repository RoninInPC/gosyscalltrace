package gosyscalltrace

import (
	"fmt"
	"strings"
)

type Format string

var (
	S Format = "%s"
	D Format = "%d"
)

type Arg struct {
	Format   Format
	Arg      string
	ForceStr bool
}

type Args []Arg

func (a Args) ToBpftraceFormat() (string, string) {
	format := ""
	args := ""
	for _, arg := range a {
		format += arg.Arg + ":" + string(arg.Format) + " "
		if arg.ForceStr {
			args += fmt.Sprintf("str(args->%s), ", arg.Arg)
		} else {
			args += fmt.Sprintf("args->%s, ", arg.Arg)
		}
	}
	args = strings.TrimSuffix(args, ", ")
	return format, args
}
