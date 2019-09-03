package output

import (
	"fmt"
	"github.com/simplycubed/vulnscan/adapters"
	"github.com/simplycubed/vulnscan/entities"
)

func ParseWarning(c entities.Command, a entities.AnalysisName, m string, args ...interface{}) (entities.Command, *entities.LogMessage) {
	return c, &entities.LogMessage{
		Level:    entities.Warn,
		Analysis: a,
		Message:  fmt.Sprintf(m, args...),
	}
}

func ParseInfo(c entities.Command, a entities.AnalysisName, m string, args ...interface{}) (entities.Command, *entities.LogMessage) {
	return c, &entities.LogMessage{
		Level:    entities.Info,
		Analysis: a,
		Message:  fmt.Sprintf(m, args...),
	}
}

func ParseError(c entities.Command, a entities.AnalysisName, e error) (entities.Command, *entities.Error) {
	return c, &entities.Error{E: e, Analysis: a}
}

func CheckNil(adapter adapters.AdapterMap) {
	if adapter.Output.Result == nil {
		adapter.Output.Result = func(command entities.Command, e entities.Entity) error {
			return nil
		}
	}
	if adapter.Output.Error == nil {
		adapter.Output.Error = func(command entities.Command, e *entities.Error) error {
			return nil
		}
	}
	if adapter.Output.Logger == nil {
		adapter.Output.Logger = func(command entities.Command, e *entities.LogMessage) error {
			return nil
		}
	}
}
