package entities

import (
	"fmt"
	"gopkg.in/go-playground/validator.v9"
)

type Error struct {
	Analysis AnalysisName `json:"analysis"`
	E        error        `json:"e" validate:"required"`
}

func (e *Error) FromMap(m map[string]interface{}) (ent Entity, err error) {
	if v, ok := m["e"]; ok {
		switch v.(type) {
		case error:
			e.E = v.(error)
		default:
			return ent, fmt.Errorf("erroneus e type, expected error, found: %T", v)
		}
	}
	return e, nil
}

func (e *Error) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"e":        e.E,
		"analysis": string(e.Analysis),
	}
}

func (e *Error) Validate() []validator.FieldError {
	return Validate(e)
}
