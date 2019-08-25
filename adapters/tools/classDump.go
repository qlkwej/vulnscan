package tools

import (
	"fmt"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
	"os"
	"os/exec"
)

func ClassDumpAdapter(command utils.Command, entity *entities.BinaryAnalysis) error {
	commandBin := getToolsFolder() + "class-dump-z"
	if entity.BinType == entities.Swift {
		commandBin = getToolsFolder() + "class-dump-swift"
	}
	if _, err := os.Stat(commandBin); os.IsNotExist(err) {
		return fmt.Errorf("class dump binary not found on %s, probably it's not installed", commandBin)
	}
	exec.Command("chmod", "777", commandBin)
	out, err := exec.Command(commandBin, command.Path).CombinedOutput()
	if err != nil {
		return err
	}
	return classDumpExtractor(string(out), entity)
}
