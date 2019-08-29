package output

import (
	"github.com/simplycubed/vulnscan/adapters"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
)

func ParseWarning(c utils.Command, a entities.AnalysisName, m string) (utils.Command, *entities.LogMessage) {
	return c, &entities.LogMessage{
		Level:    entities.Warn,
		Analysis: a,
		Message:  m,
	}
}

func ParseInfo(c utils.Command, a entities.AnalysisName, m string) (utils.Command, *entities.LogMessage) {
	return c, &entities.LogMessage{
		Level:    entities.Inf,
		Analysis: a,
		Message:  m,
	}
}

func ParseError(c utils.Command, a entities.AnalysisName, e error) (utils.Command, *entities.Error) {
	return c, &entities.Error{E: e, Analysis: a}
}

func CheckNil(adapter adapters.AdapterMap) {
	if adapter.Output.Result == nil {
		adapter.Output.Result = func(command utils.Command, e entities.Entity) error {
			return nil
		}
	}
	if adapter.Output.Error == nil {
		adapter.Output.Error = func(command utils.Command, e *entities.Error) error {
			return nil
		}
	}
	if adapter.Output.Logger == nil {
		adapter.Output.Logger = func(command utils.Command, e *entities.LogMessage) error {
			return nil
		}
	}
}
