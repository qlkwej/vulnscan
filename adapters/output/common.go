package output

import (
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
)

func ParseWarning(c utils.Command, a entities.AnalysisName, m string) (utils.Command, *entities.LogMessage) {
	return c, &entities.LogMessage{
		Level:   entities.Warn,
		Analysis:a,
		Message: m,
	}
}

func ParseInfo(c utils.Command, a entities.AnalysisName, m string) (utils.Command, *entities.LogMessage) {
	return c, &entities.LogMessage{
		Level:   entities.Inf,
		Analysis:a,
		Message: m,
	}
}


func ParseError(c utils.Command, a entities.AnalysisName, e error) (utils.Command, *entities.Error) {
	return c, &entities.Error{E:e, Analysis:a}
}

