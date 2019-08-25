package output

import (
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
)

func ParseWarning(a entities.AnalysisName, m string) (utils.Command, *entities.LogMessage) {
	return utils.Command{}, &entities.LogMessage{
		Level:   entities.W,
		Analysis:a,
		Message: m,
	}
}

func ParseInfo(a entities.AnalysisName, m string) (utils.Command, *entities.LogMessage) {
	return utils.Command{}, &entities.LogMessage{
		Level:   entities.I,
		Analysis:a,
		Message: m,
	}
}


func ParseError(a entities.AnalysisName, e error) (utils.Command, *entities.Error) {
	return utils.Command{}, &entities.Error{E:e, Analysis:a}
}

