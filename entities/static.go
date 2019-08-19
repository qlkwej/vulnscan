package entities

import (
	"fmt"
	"gopkg.in/go-playground/validator.v9"
)

type StaticAnalysis struct {
	HasBinary bool           `json:"has_binary"`
	HasCode   bool           `json:"has_code"`
	HasFiles  bool           `json:"has_files"`
	HasPlist  bool           `json:"has_plist"`
	HasVirus  bool           `json:"has_virus"`
	HasStore  bool           `json:"has_store"`
	Binary    BinaryAnalysis `json:"binary"`
	Code      CodeAnalysis   `json:"code"`
	Files     FileAnalysis   `json:"files"`
	Plist     PListAnalysis  `json:"plist"`
	Virus     VirusAnalysis  `json:"virus"`
	Store     StoreAnalysis  `json:"store"`
}

func (e *StaticAnalysis) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"has_binary": e.HasBinary,
		"has_code":   e.HasCode,
		"has_files":  e.HasFiles,
		"has_plist":  e.HasPlist,
		"has_virus":  e.HasVirus,
		"has_store":  e.HasStore,
		"binary":     e.Binary.ToMap(),
		"code":       e.Code.ToMap(),
		"files":      e.Files.ToMap(),
		"plist":      e.Plist.ToMap(),
		"virus":      e.Virus.ToMap(),
		"store":      e.Store.ToMap(),
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
			e.HasBinary = true
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
			e.HasCode = true
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
			e.HasFiles = true
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
			e.HasPlist = true
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
			e.HasVirus = true
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
			e.HasStore = true
		default:
			return ent, fmt.Errorf("erroneus store type, expected map[string]interface{}, found: %T", v)
		}
	}
	return e, err
}

func (e *StaticAnalysis) Validate() []validator.FieldError {
	var errors []validator.FieldError
	if e.HasStore {
		errors = append(errors, Validate(&e.Store)...)
	}
	if e.HasVirus {
		errors = append(errors, Validate(&e.Virus)...)
	}
	if e.HasPlist {
		errors = append(errors, Validate(&e.Plist)...)
	}
	if e.HasFiles {
		errors = append(errors, Validate(&e.Files)...)
	}
	if e.HasCode {
		errors = append(errors, Validate(&e.Code)...)
	}
	if e.HasBinary {
		errors = append(errors, Validate(&e.Code)...)
	}
	return errors
}
