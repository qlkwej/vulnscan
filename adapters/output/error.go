package output

import (
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
)

func ErrorAdapter(command utils.Command, entity *entities.Error) (entities.Entity, error) {
	return BasicLoggerAdapter(command, &entities.LogMessage{
		Level:   entities.E,
		Message: entity.E.Error(),
	})
}
