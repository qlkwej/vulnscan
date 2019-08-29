package entities

import (
	"fmt"
	"gopkg.in/go-playground/validator.v9"
)

type (
	LogLevel     int
	AnalysisName string

	LogMessage struct {
		Level    LogLevel     `json:"level"`
		Analysis AnalysisName `json:"analysis"`
		Message  string       `json:"message" validate:"min=1"`
	}
)

const (
	Und  LogLevel = iota // 0: Logs nothing
	Inf                  // 1: Logs Info, Warnings and Errors
	Warn                 // 2: Logs Warning and Errors
	Err                  // 3: Logs Errors

	Binary AnalysisName = "Binary Analysis"
	Code   AnalysisName = "Code Analysis"
	Files  AnalysisName = "Files Analysis"
	Static AnalysisName = "Static Analysis"
	Plist  AnalysisName = "Plist Analysis"
	Store  AnalysisName = "Store Analysis"
	None   AnalysisName = ""
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
	if v, ok := m["analysis"]; ok {
		switch v.(type) {
		case string:
			e.Analysis = AnalysisName(v.(string))
		default:
			return ent, fmt.Errorf("erroneus message type, expected string, found: %T", v)
		}
	}
	return e, err
}

func (e *LogMessage) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"level":    int(e.Level),
		"analysis": string(e.Analysis),
		"message":  e.Message,
	}
}

func (e *LogMessage) Validate() []validator.FieldError {
	return Validate(e)
}
