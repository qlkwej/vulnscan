package entities

import (
	"fmt"
	"gopkg.in/go-playground/validator.v9"
)

type FileAnalysis struct {
	Files 			[]string `json:"files" validate:"min=1"`
	Certifications 	[]string `json:"certifications" validate:"required"`
	Databases 		[]string `json:"databases" validate:"required"`
	PLists 			[]string `json:"plists" validate:"required"`
}

func (e *FileAnalysis) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"files": e.Files,
		"certifications": e.Certifications,
		"databases": e.Databases,
		"plists": e.PLists,
	}
}

func (e *FileAnalysis) FromMap(m map[string]interface{}) (ent Entity, err error) {
	if v, ok := m["files"]; ok {
		switch v.(type) {
		case []string:
			e.Files = v.([]string)
		default:
			return ent, fmt.Errorf("erroneus files type, expected string, found: %T", v)
		}
	}
	if v, ok := m["certifications"]; ok {
		switch v.(type) {
		case []string:
			e.Certifications = v.([]string)
		default:
			return ent, fmt.Errorf("erroneus certifications type, expected string, found: %T", v)
		}
	}
	if v, ok := m["databases"]; ok {
		switch v.(type) {
		case []string:
			e.Databases = v.([]string)
		default:
			return ent, fmt.Errorf("erroneus databases type, expected string, found: %T", v)
		}
	}
	if v, ok := m["plists"]; ok {
		switch v.(type) {
		case []string:
			e.PLists = v.([]string)
		default:
			return ent, fmt.Errorf("erroneus plists type, expected string, found: %T", v)
		}
	}
	return e, err
}

func (e *FileAnalysis) Validate() []validator.FieldError {
	return Validate(e)
}


