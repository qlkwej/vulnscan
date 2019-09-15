package tools

import (
	"github.com/simplycubed/vulnscan/entities"
	"strings"
)

func JtoolLibsAdapter(command entities.Command, entity *entities.BinaryAnalysis) error {
	out, err := performJtoolAnalysis(command, [][]string{{"-arch", "arm", "-L", "-v", command.Path}})
	if err != nil {
		return err // already formated in performJtoolAnalysis, so just return
	}
	libs := strings.Split(out, "\n")
	for _, l := range libs {
		if len(l) > 0 {
			entity.Libraries = append(entity.Libraries, l)
		}
	}
	return nil
}

func JtoolHeadersAdapter(command entities.Command, entity *entities.BinaryAnalysis) error {
	out, err := performJtoolAnalysis(command, [][]string{{"-arch", "arm", "-h", "-v", command.Path}})
	if err != nil {
		return err // already formated in performJtoolAnalysis
	}
	return headerExtractor(out, entity)
}

func JtoolSymbolsAdapter(command entities.Command, entity *entities.BinaryAnalysis) error {
	out, err := performJtoolAnalysis(command, [][]string{
		{"-arch", "arm", "-h", "-v", command.Path},
		{"-arch", "arm", "-lazy_bind", "-v", command.Path},
	})
	if err != nil {
		return err // already formated in performJtoolAnalysis
	}
	return symbolExtractor(out, entity)
}

func JtoolClassDumpAdapter(command entities.Command, entity *entities.BinaryAnalysis) error {
	out, err := performJtoolAnalysis(command, [][]string{
		{"-arch", "arm", "-d", "objc", "-v", command.Path},
	})
	if err != nil {
		return err // already formated in performJtoolAnalysis
	}
	return classDumpExtractor(out, entity)
}
