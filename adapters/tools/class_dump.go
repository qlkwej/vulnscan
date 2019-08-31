package tools

import (
	"fmt"
	"github.com/simplycubed/vulnscan/entities"
	"os"
	"os/exec"
)

func ClassDumpAdapter(command entities.Command, entity *entities.BinaryAnalysis) error {
	commandBin := command.Tools + "class-dump-z"
	if entity.BinType == entities.Swift {
		commandBin = command.Tools + "class-dump-swift"
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
