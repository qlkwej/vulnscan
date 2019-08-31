package mocks

import (
	"github.com/simplycubed/vulnscan/entities"
	"github.com/stretchr/testify/assert"
)

func ErrorAdapter(command entities.Command, entity *entities.Error) error {
	if !assert.NoError(command.T, entity.E) {
		return entity.E
	}
	return nil
}

func LogAdapter(command entities.Command, entity *entities.LogMessage) error {
	var level string
	switch entity.Level {
	case entities.Inf:
		level = "INFO| "
	case entities.Warn:
		level = "WARN| "
	case entities.Err:
		level = "ERROR| "
	default:
		level = ""
	}
	command.T.Logf("%s%s: %s", level, entity.Analysis, entity.Message)
	return nil
}
