package tools

import (
	"fmt"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
	"os/exec"
	"runtime"
	"strings"
)

func performOtoolAnalysis(path, arg string) (out string, err error) {
	if platform := runtime.GOOS; platform != "darwin" {
		return out, fmt.Errorf("platform %s not supported", platform)
	}
	outB, err := exec.Command("otool", arg, path).CombinedOutput()
	return string(outB), err
}


func OtoolLibsAdapter(command utils.Command, entity *entities.BinaryAnalysis) (entities.Entity, error) {
	out, e := performOtoolAnalysis(command.Path, "L")
	if e != nil {
		return nil, e
	}
	entity.Libraries = strings.Split(out, "\n")
	return entity, nil
}

func OtoolHeaderAdapter(command utils.Command, entity *entities.BinaryAnalysis) (entities.Entity, error) {
	out, e := performOtoolAnalysis(command.Path, "-hv")
	if e != nil {
		return nil, e
	}
	return headerExtractor(out, entity)
}


func OtoolSymbolsAdapter(command utils.Command, entity *entities.BinaryAnalysis) (entities.Entity, error) {
	out, e := performOtoolAnalysis(command.Path, "-Iv")
	if e != nil {
		return nil, e
	}
	return symbolExtractor(out, entity)
}
