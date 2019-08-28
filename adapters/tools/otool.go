package tools

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
)


func OtoolLibsAdapter(command utils.Command, entity *entities.BinaryAnalysis) error {
	out, e := performOtoolAnalysis(command.Path, "-L")
	if e != nil {
		return e
	}
	entity.Libraries = strings.Split(out, "\n")
	return nil
}

func OtoolHeaderAdapter(command utils.Command, entity *entities.BinaryAnalysis) error {
	out, e := performOtoolAnalysis(command.Path, "-hv")
	if e != nil {
		return e
	}
	return headerExtractor(out, entity)
}


func OtoolSymbolsAdapter(command utils.Command, entity *entities.BinaryAnalysis) error {
	out, e := performOtoolAnalysis(command.Path, "-Iv")
	if e != nil {
		return e
	}
	return symbolExtractor(out, entity)
}


func performOtoolAnalysis(path, arg string) (out string, err error) {
	if platform := runtime.GOOS; platform != "darwin" {
		return out, fmt.Errorf("platform %s not supported", platform)
	}
	outB, err := exec.Command("otool", arg, path).CombinedOutput()
	return string(outB), err
}

