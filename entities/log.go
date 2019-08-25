package entities

import (
	"fmt"
	"gopkg.in/go-playground/validator.v9"
)

type (
	LogLevel int
	LogMessage struct {
		Level LogLevel `json:"level"`
		Message string `json:"message" validate:"min=1"`
	}
)

const (
	U LogLevel = iota  // 0: Logs nothing
	I // 1: Logs Info, Warnings and Errors
	W // 2: Logs Warning and Errors
	E // 3: Logs Errors
)


func (e *LogMessage) FromMap(m map[string]interface{}) (ent Entity, err error) {
	if v, ok := m["level"]; ok {
		switch v.(type) {
		case int:
			e.Level = LogLevel(v.(int))
		case int8:
			e.Level = LogLevel(int(v.(int8)))
		case int16:
			e.Level = LogLevel(int(v.(int16)))
		case int32:
			e.Level = LogLevel(int(v.(int32)))
		case int64:
			e.Level = LogLevel(int(v.(int64)))
		case LogLevel:
			e.Level = v.(LogLevel)
		default:
			return ent, fmt.Errorf("erroneus level type, expected int, found: %T", v)
		}
	}
	if v, ok := m["message"]; ok {
		switch v.(type) {
		case string:
			e.Message = v.(string)
		default:
			return ent, fmt.Errorf("erroneus message type, expected string, found: %T", v)
		}
	}
	return e, err
}

func (e *LogMessage) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"level": int(e.Level),
		"message": e.Message,
	}
}

func (e *LogMessage) Validate() []validator.FieldError {
	return Validate(e)
}
