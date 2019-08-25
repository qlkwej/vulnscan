package output

import (
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
)

func BasicErrorAdapter(command utils.Command, entity *entities.Error) error {
	if err := entity.E; err != nil {
		_ = BasicLoggerAdapter(command, &entities.LogMessage{
			Level:   entities.Err,
			Analysis: entity.Analysis,
			Message: entity.E.Error(),
		})
		return err
	}
	return nil
}
