package tools

import (
	"github.com/simplycubed/vulnscan/entities"
	"strings"
)

func JtoolLibsAdapter(command entities.Command, entity *entities.BinaryAnalysis) error {
	out, err := performJtoolAnalysis([][]string{{"-arch", "arm", "-L", "-v", command.Path}})
	if err != nil {
		return err
	}
	entity.Libraries = strings.Split(out, "\n")
	return nil
}

func JtoolHeadersAdapter(command entities.Command, entity *entities.BinaryAnalysis) error {
	out, err := performJtoolAnalysis([][]string{{"-arch", "arm", "-h", "-v", command.Path}})
	if err != nil {
		return err
	}
	return headerExtractor(out, entity)
}

func JtoolSymbolsAdapter(command entities.Command, entity *entities.BinaryAnalysis) error {
	out, err := performJtoolAnalysis([][]string{
		{"-arch", "arm", "-h", "-v", command.Path},
		{"-arch", "arm", "-lazy_bind", "-v", command.Path},
	})
	if err != nil {
		return err
	}
	return symbolExtractor(out, entity)
}

func JtoolClassDumpAdapter(command entities.Command, entity *entities.BinaryAnalysis) error {
	out, err := performJtoolAnalysis([][]string{
		{"-arch", "arm", "-d", "objc", "-v", command.Path},
	})
	if err != nil {
		return err
	}
	return classDumpExtractor(out, entity)
}
