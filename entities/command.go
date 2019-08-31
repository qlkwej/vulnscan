package entities

import (
	"fmt"
	"gopkg.in/go-playground/validator.v9"
	"io"
	"testing"
)

type (

	AnalysisCheck string

	Command struct {
		Path          string 				 `json:"path" validate:"min=1"`
		AppName       string 				 `json:"app_name"`
		AppId         string 				 `json:"app_id"`
		Country       string 				 `json:"country"`
		VirusTotalKey string 				 `json:"virus_total_key"`
		Source        bool 					 `json:"source"`
		Analysis      map[AnalysisCheck]bool `json:"analysis" validate:"valid_analysis"`
		CheckDomains  bool 					 `json:"check_domains"`
		Output        io.Writer 			 `json:"output"`
		T             *testing.T 			 `json:"t"`
	}
)

const (
	DoPList  AnalysisCheck = "DoPList"
	DoFiles  AnalysisCheck = "DoFiles"
	DoCode   AnalysisCheck = "DoCode"
	DoBinary AnalysisCheck = "DoAnalysis"
	DoStore  AnalysisCheck = "DoStore"
)

var (
	validAnalysisChecks = map[AnalysisCheck]bool {
		DoPList: true,
		DoFiles: true,
		DoCode: true,
		DoBinary: true,
		DoStore: true,
	}
)

func analysisCheckValidator(fl validator.FieldLevel) bool {
	repr := fl.Field().Interface().(map[AnalysisCheck]bool)
	if len(repr) == 0 {
		return false
	}
	for k, _ := range repr {
		if !validAnalysisChecks[k] {
			return false
		}
	}
	return true
}

func (c Command) ToMap() map[string]interface{} {
	m := map[string]interface{}{
		"path": c.Path,
		"app_name": c.AppName,
		"app_id": c.AppId,
		"country": c.Country,
		"virus_total_key": c.VirusTotalKey,
		"source": c.Source,
		"analysis": map[string]bool{},
		"check_domains": c.CheckDomains,
		"output": c.Output,
		"t": c.T,
	}
	for k, v := range c.Analysis {
		m["analysis"].(map[string]bool)[string(k)] = v
	}
	return m
}

func (c Command) FromMap(m map[string]interface{}) (ent Entity, err error) {
	if v, ok := m["path"]; ok {
		switch v.(type) {
		case string:
			c.Path = v.(string)
		default:
			return ent, fmt.Errorf("erroneus path type, expected string, found: %T", v)
		}
	}
	if v, ok := m["app_name"]; ok {
		switch v.(type) {
		case string:
			c.AppName = v.(string)
		default:
			return ent, fmt.Errorf("erroneus app name type, expected string, found: %T", v)
		}
	}
	if v, ok := m["app_id"]; ok {
		switch v.(type) {
		case string:
			c.AppId = v.(string)
		default:
			return ent, fmt.Errorf("erroneus app id type, expected string, found: %T", v)
		}
	}
	if v, ok := m["country"]; ok {
		switch v.(type) {
		case string:
			c.Country = v.(string)
		default:
			return ent, fmt.Errorf("erroneus country type, expected string, found: %T", v)
		}
	}
	if v, ok := m["virus_total_key"]; ok {
		switch v.(type) {
		case string:
			c.VirusTotalKey = v.(string)
		default:
			return ent, fmt.Errorf("erroneus virus_total_key type, expected string, found: %T", v)
		}
	}
	if v, ok := m["source"]; ok {
		switch v.(type) {
		case bool:
			c.Source = v.(bool)
		default:
			return ent, fmt.Errorf("erroneus source type, expected bool, found: %T", v)
		}
	}
	if v, ok := m["analysis"]; ok {
		switch v.(type) {
		case map[string]bool:
			c.Analysis = map[AnalysisCheck]bool{}
			for k, v := range v.(map[string]bool) {
				c.Analysis[AnalysisCheck(k)] = v
			}
		default:
			return ent, fmt.Errorf("erroneus analysis type, expected map[string]bool (set), found: %T", v)
		}
	}
	if v, ok := m["check_domains"]; ok {
		switch v.(type) {
		case bool:
			c.CheckDomains = v.(bool)
		default:
			return ent, fmt.Errorf("erroneus check domains type, expected bool, found: %T", v)
		}
	}
	if v, ok := m["output"]; ok {
		switch v.(type) {
		case io.Writer:
			c.Output = v.(io.Writer)
		default:
			return ent, fmt.Errorf("erroneus output type, expected bool, found: %T", v)
		}
	}
	if v, ok := m["t"]; ok {
		switch v.(type) {
		case *testing.T:
			c.T = v.(*testing.T)
		default:
			return ent, fmt.Errorf("erroneus t type, expected *testing.T, found: %T", v)
		}
	}
	return c, nil
}


func (c Command) Validate() []validator.FieldError {
	return Validate(c)
}
