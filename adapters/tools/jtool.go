package tools

import (
	"flag"
	"fmt"
	"github.com/kardianos/osext"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
	"os"
	"os/exec"
	"strings"
)


// Returns the folder where the program external binary tools (jtool, class-dump) is present. By default, depending on
// the environment where the program is executing (testing/not testing) the tools will be in vulnscan/tools/tools
// (testing) or in a sibling folder of the vulnscan binary. The function also looks for a folder configured using the
// configuration file.
func getToolsFolder() string {
	if tf := utils.Configuration.ToolsFolder; tf != "" {
		return tf
	}
	var parentFolder string
	if flag.Lookup("test.v") == nil {
		parentFolder, _ = osext.ExecutableFolder()
	} else {
		parentFolder, _ = utils.FindMainFolder()
	}
	return parentFolder + string(os.PathSeparator) + "tools" + string(os.PathSeparator)
}

func performJtoolAnalysis(args [][]string) (out string, err error) {
	command := getToolsFolder() + "jtool"
	if _, err := os.Stat(command); os.IsNotExist(err) {
		return out, fmt.Errorf("jtool not found on %s, probably it's not installed", command)
	}
	var sb strings.Builder
	for _, arg := range args {
		if out, e := exec.Command(command, arg...).CombinedOutput(); e != nil {
			return string(out), e
		} else {
			sb.WriteString(string(out))
			sb.WriteString("\n")
		}
	}
	return sb.String(), nil
}

func JtoolLibsAdapter(command utils.Command, entity *entities.BinaryAnalysis) (entities.Entity, error) {
	out, err := performJtoolAnalysis([][]string{{"-arch", "arm", "-L", "-v", command.Path}})
	if err != nil {
		return nil, err
	}
	entity.Libraries = strings.Split(out, "\n")
	return entity, nil
}

func JtoolHeadersAdapter(command utils.Command, entity *entities.BinaryAnalysis) (entities.Entity, error) {
	out, err := performJtoolAnalysis([][]string{{"-arch", "arm", "-h", "-v", command.Path}})
	if err != nil {
		return nil, err
	}
	return headerExtractor(out, entity)
}

func JtoolSymbolsAdapter(command utils.Command, entity *entities.BinaryAnalysis) (entities.Entity, error) {
	out, err := performJtoolAnalysis([][]string{
		{"-arch", "arm", "-h", "-v", command.Path},
		{"-arch", "arm", "-lazy_bind", "-v", command.Path},
	})
	if err != nil {
		return nil, err
	}
	return symbolExtractor(out, entity)
}

func JtoolClassDump(command utils.Command, entity *entities.BinaryAnalysis) (entities.Entity, error) {
	out, err := performJtoolAnalysis([][]string{
		{"-arch", "arm", "-d", "objc", "-v", command.Path},
	})
	if err != nil {
		return nil, err
	}
	return classDumpExtractor(out, entity)
}

