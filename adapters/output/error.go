package output

import (
	"fmt"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
)

func ErrorAdapter(command utils.Command, entity *entities.Error) error {
	if err := entity.E; err != nil {
		_ = BasicLoggerAdapter(command, &entities.LogMessage{
			Level:   entities.E,
			Analysis: entities.None,
			Message: fmt.Sprintf("Error on %s: %s", entity.Analysis, entity.E.Error()),
		})
		return err
	}
	return nil
}
