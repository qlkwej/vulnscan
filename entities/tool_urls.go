package entities

import (
	"fmt"
	"gopkg.in/go-playground/validator.v9"
)

type ToolUrls struct {
	JTool string `json:"jtool" validate:"url"`
	ClassDumpZ string `json:"class-dump-z" validate:"url"`
	ClassDumpSwift string `json:"class-dump-swift" validate:"url"`
}


func (e *ToolUrls) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"j_tool": e.JTool,
		"class_dump_z": e.ClassDumpZ,
		"class_dump_swift": e.ClassDumpSwift,
	}
}

func (e *ToolUrls) FromMap(m map[string]interface{}) (ent Entity, err error) {
	if v, ok := m["class_dump_z"]; ok {
		switch v.(type) {
		case string:
			e.ClassDumpZ = v.(string)
		default:
			return ent, fmt.Errorf("erroneus class_dump_z url type, expected string, found: %T", v)
		}
	}
	if v, ok := m["class_dump_swift"]; ok {
		switch v.(type) {
		case string:
			e.ClassDumpSwift = v.(string)
		default:
			return ent, fmt.Errorf("erroneus class_dump_swift url type, expected string, found: %T", v)
		}
	}
	if v, ok := m["j_tool"]; ok {
		switch v.(type) {
		case string:
			e.JTool = v.(string)
		default:
			return ent, fmt.Errorf("erroneus jtool url type, expected string, found: %T", v)
		}
	}
	return e, nil
}

func (e *ToolUrls) Validate() []validator.FieldError {
	return Validate(e)
}
