package entities

import (
	"fmt"
	"gopkg.in/go-playground/validator.v9"
)

type StaticAnalysis struct {
	Binary BinaryAnalysis `json:"binary"`
	Code CodeAnalysis `json:"code"`
	Files FileAnalysis `json:"files"`
	Plist PListAnalysis `json:"plist"`
	Virus VirusAnalysis `json:"virus"`
	Store StoreAnalysis `json:"store"`
}

func (e *StaticAnalysis) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"binary": e.Binary.ToMap(),
		"code": e.Code.ToMap(),
		"files": e.Files.ToMap(),
		"plist": e.Plist.ToMap(),
		"virus": e.Virus.ToMap(),
		"store": e.Store.ToMap(),
	}
}

func (e *StaticAnalysis) FromMap(m map[string]interface{}) (ent Entity, err error) {
	if v, ok := m["binary"]; ok {
		switch v.(type) {
		case map[string]interface{}:
			r, err := (&BinaryAnalysis{}).FromMap(v.(map[string]interface{}))
			if err != nil {
				return ent, err
			}
			e.Binary = *r.(*BinaryAnalysis)
		default:
			return ent, fmt.Errorf("erroneus binary type, expected map[string]interface{}, found: %T", v)
		}
	}
	if v, ok := m["code"]; ok {
		switch v.(type) {
		case map[string]interface{}:
			r, err := (&CodeAnalysis{}).FromMap(v.(map[string]interface{}))
			if err != nil {
				return ent, err
			}
			e.Code = *r.(*CodeAnalysis)
		default:
			return ent, fmt.Errorf("erroneus code type, expected map[string]interface{}, found: %T", v)
		}
	}
	if v, ok := m["files"]; ok {
		switch v.(type) {
		case map[string]interface{}:
			r, err := (&FileAnalysis{}).FromMap(v.(map[string]interface{}))
			if err != nil {
				return ent, err
			}
			e.Files = *r.(*FileAnalysis)
		default:
			return ent, fmt.Errorf("erroneus files type, expected map[string]interface{}, found: %T", v)
		}
	}
	if v, ok := m["plist"]; ok {
		switch v.(type) {
		case map[string]interface{}:
			r, err := (&PListAnalysis{}).FromMap(v.(map[string]interface{}))
			if err != nil {
				return ent, err
			}
			e.Plist = *r.(*PListAnalysis)
		default:
			return ent, fmt.Errorf("erroneus plist type, expected map[string]interface{}, found: %T", v)
		}
	}
	if v, ok := m["virus"]; ok {
		switch v.(type) {
		case map[string]interface{}:
			r, err := (&VirusAnalysis{}).FromMap(v.(map[string]interface{}))
			if err != nil {
				return ent, err
			}
			e.Virus = *r.(*VirusAnalysis)
		default:
			return ent, fmt.Errorf("erroneus virus type, expected map[string]interface{}, found: %T", v)
		}
	}
	if v, ok := m["store"]; ok {
		switch v.(type) {
		case map[string]interface{}:
			r, err := (&StoreAnalysis{}).FromMap(v.(map[string]interface{}))
			if err != nil {
				return ent, err
			}
			e.Store = *r.(*StoreAnalysis)
		default:
			return ent, fmt.Errorf("erroneus store type, expected map[string]interface{}, found: %T", v)
		}
	}
	return e, err
}

func (e *StaticAnalysis) Validate() []validator.FieldError {
	return Validate(e)
}



