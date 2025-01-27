package gosyscalltrace

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var pathSys = "/sys/kernel/tracing/events/syscalls/"
var fileExit = "exit.json"
var fileEnter = "enter.json"

func GetDirs(path string) []string {
	namesOfDir := make([]string, 0)
	filepath.Walk(path, func(wPath string, info os.FileInfo, err error) error {

		// Обход директории без вывода
		if wPath == path {
			return nil
		}
		if info == nil {
			return err
		}
		if info.IsDir() {
			namesOfDir = append(namesOfDir, info.Name())
			return filepath.SkipDir
		}
		return nil
	})
	return namesOfDir
}

func getArgsByEnter(path string) string {
	filestr, err := os.ReadFile(pathSys + path + "/format")
	if err != nil {
		panic(err)
	}
	ss := regexp.MustCompile("REC->(.*?)\\)").FindAllString(string(filestr), -1)
	args := ""
	for _, s1 := range ss {
		s1 = strings.Replace(s1, "REC->", "", -1)
		s1 = strings.Replace(s1, ")", "", -1)
		args += s1 + " "
	}
	return args
}

func getArgsByExit(path string) string {
	filestr, err := os.ReadFile(pathSys + path + "/format")
	if err != nil {
		panic(err)
	}
	ss := regexp.MustCompile("REC->(.*)").FindAllString(string(filestr), -1)
	args := ""
	for _, s1 := range ss {
		s1 = strings.Replace(s1, "REC->", "", -1)
		args += s1 + " "
	}
	return args
}

func InitSyscalls() {
	dirs := GetDirs(pathSys)
	exit := map[string]string{}
	enter := map[string]string{}
	for _, dir := range dirs {
		if strings.Contains(dir, "sys_enter_") {
			enter[strings.Replace(dir, "sys_enter_", "", -1)] = getArgsByEnter(dir)
		}
		if strings.Contains(dir, "sys_exit") {
			exit[strings.Replace(dir, "sys_exit_ ", "", -1)] = getArgsByExit(dir)
		}
	}
	log.Println("Initialized syscalls enter and exit with args\n")
	log.Println("sys_enter:", enter)
	log.Println("sys_exit:", exit)

	SetSyscallsEnter(enter)
	SetSyscallsExit(exit)
}

func saveMapJson(m map[string]string, file string) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	err = os.WriteFile(file, b, 777)
	if err != nil {
		return err
	}
	return nil
}

func readMapFromJson(file string) (map[string]string, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	m := make(map[string]string)
	err = json.Unmarshal(b, &m)
	if err != nil {
		return nil, err
	}
	return m, nil
}
