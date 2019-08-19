package entities

import (
	"fmt"
	"gopkg.in/go-playground/validator.v9"
)

type (
	Level string
	Match func(string) bool

	CodeRule struct {
		// Description of the code rule
		Description string `json:"description" validate:"min=1"`
		// level of the issue
		Level Level   `json:"level"       validate:"required,valid_levels"`
		Cvss  float64 `json:"cvss"        validate:"required"`
		Cwe   string  `json:"cwe"         validate:"startswith=CWE-"`
	}

	CodeMatcher struct {
		CodeRule
		// func (string) bool to call against a string to do the match
		Match Match `json:"match" validate:"required"`
	}

	CodeFinding struct {
		CodeRule
		Paths []string `json:"paths" validate:"min=1"`
	}

	ApiRule struct {
		Description string `json:"description" validate:"min=1"`
	}

	ApiMatcher struct {
		ApiRule
		Match Match `json:"match" validate:"required"`
	}

	ApiFinding struct {
		ApiRule
		Paths []string `json:"paths" validate:"min=1"`
	}

	UrlFinding struct {
		Url   string   `json:"url" validate:"min=1"`
		Paths []string `json:"paths" validate:"min=1"`
	}

	EmailFinding struct {
		Email string   `json:"email" validate:"min=1"`
		Paths []string `json:"paths" validate:"min=1"`
	}

	CodeAnalysis struct {
		Codes      []CodeFinding  `json:"codes" validate:"required,dive"`
		Apis       []ApiFinding   `json:"apis" validate:"required,dive"`
		Urls       []UrlFinding   `json:"urls" validate:"required,dive"`
		Emails     []EmailFinding `json:"emails" validate:"required,dive"`
		BadDomains []string       `json:"bad_domains"`
	}
)

const (
	HighLevel    Level = "High"
	WarningLevel Level = "Warning"
	InfoLevel    Level = "Info"
	GoodLevel    Level = "Good"
)

var validLevelValues = map[Level]bool{
	HighLevel:    true,
	WarningLevel: true,
	InfoLevel:    true,
	GoodLevel:    true,
}

func levelValidator(fl validator.FieldLevel) bool {
	return validLevelValues[Level(fl.Field().String())]
}

func (e *CodeRule) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"description": e.Description,
		"level":       string(e.Level),
		"cvss":        e.Cvss,
		"cwe":         e.Cwe,
	}
}

func (e *CodeRule) FromMap(m map[string]interface{}) (ent Entity, err error) {
	if v, ok := m["description"]; ok {
		switch v.(type) {
		case string:
			e.Description = v.(string)
		default:
			return ent, fmt.Errorf("erroneus desc type, expected string, found: %T", v)
		}
	}
	if v, ok := m["level"]; ok {
		switch v.(type) {
		case Level:
			e.Level = v.(Level)
		case string:
			e.Level = Level(v.(string))
		default:
			return ent, fmt.Errorf("erroneus level type, expected string/Level, found: %T", v)
		}
	}
	if v, ok := m["cvss"]; ok {
		switch v.(type) {
		case float64:
			e.Cvss = v.(float64)
		case float32:
			e.Cvss = float64(v.(float32))
		case int:
			e.Cvss = float64(v.(int))
		case int8:
			e.Cvss = float64(v.(int8))
		case int16:
			e.Cvss = float64(v.(int16))
		case int32:
			e.Cvss = float64(v.(int32))
		case int64:
			e.Cvss = float64(v.(int64))
		default:
			return ent, fmt.Errorf("erroneus cvss type, expected float, found: %T", v)
		}
	}
	if v, ok := m["cwe"]; ok {
		switch v.(type) {
		case string:
			e.Cwe = v.(string)
		default:
			return ent, fmt.Errorf("erroneus cwe type, expected string, found: %T", v)
		}
	}
	return e, err
}

func (e *CodeRule) Validate() []validator.FieldError {
	return Validate(e)
}

func (e *CodeMatcher) ToMap() map[string]interface{} {
	crMap := e.CodeRule.ToMap()
	crMap["match"] = e.Match
	return crMap
}

func (e *CodeMatcher) FromMap(m map[string]interface{}) (ent Entity, err error) {
	codeRule, err := (&CodeRule{}).FromMap(m)
	if err != nil {
		return ent, err
	}
	e.CodeRule = *codeRule.(*CodeRule)
	if v, ok := m["match"]; ok {
		switch v.(type) {
		case func(string) bool:
			e.Match = v.(func(string) bool)
		default:
			return ent, fmt.Errorf("erroneus match type, expected func(string)bool, found: %T", v)
		}
	}
	return e, err

}

func (e *CodeMatcher) Validate() []validator.FieldError {
	return Validate(e)
}

func (e *CodeFinding) ToMap() map[string]interface{} {
	crMap := e.CodeRule.ToMap()
	crMap["paths"] = e.Paths
	return crMap
}

func (e *CodeFinding) FromMap(m map[string]interface{}) (ent Entity, err error) {
	codeRule, err := (&CodeRule{}).FromMap(m)
	if err != nil {
		return ent, err
	}
	e.CodeRule = *codeRule.(*CodeRule)
	if v, ok := m["paths"]; ok {
		switch v.(type) {
		case []string:
			e.Paths = v.([]string)
		default:
			return ent, fmt.Errorf("erroneus paths type, expected []string, found: %T", v)
		}
	}
	return e, err
}

func (e *CodeFinding) Validate() []validator.FieldError {
	return Validate(e)
}

func (e *ApiRule) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"description": e.Description,
	}
}

func (e *ApiRule) FromMap(m map[string]interface{}) (ent Entity, err error) {
	if v, ok := m["description"]; ok {
		switch v.(type) {
		case string:
			e.Description = v.(string)
		default:
			return ent, fmt.Errorf("erroneus description type, expected string, found: %T", v)
		}
	}
	return e, err
}

func (e *ApiRule) Validate() []validator.FieldError {
	return Validate(e)
}

func (e *ApiMatcher) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"description": e.Description,
		"match":       e.Match,
	}
}

func (e *ApiMatcher) FromMap(m map[string]interface{}) (ent Entity, err error) {
	apiRule, err := (&ApiRule{}).FromMap(m)
	e.ApiRule = *(apiRule.(*ApiRule))
	if v, ok := m["match"]; ok {
		switch v.(type) {
		case func(string) bool:
			e.Match = v.(func(string) bool)
		default:
			return ent, fmt.Errorf("erroneus match type, expected func(string)bool, found: %T", v)
		}
	}
	return e, err
}

func (e *ApiMatcher) Validate() []validator.FieldError {
	return Validate(e)
}

func (e *ApiFinding) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"description": e.Description,
		"paths":       e.Paths,
	}
}

func (e *ApiFinding) FromMap(m map[string]interface{}) (ent Entity, err error) {
	apiRule, err := (&ApiRule{}).FromMap(m)
	if err != nil {
		return ent, err
	}
	e.ApiRule = *(apiRule.(*ApiRule))
	if v, ok := m["paths"]; ok {
		switch v.(type) {
		case []string:
			e.Paths = v.([]string)
		default:
			return ent, fmt.Errorf("erroneus paths type, expected []string, found: %T", v)
		}
	}
	return e, err
}

func (e *ApiFinding) Validate() []validator.FieldError {
	return Validate(e)
}

func (e *UrlFinding) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"url":   e.Url,
		"paths": e.Paths,
	}
}

func (e *UrlFinding) FromMap(m map[string]interface{}) (ent Entity, err error) {
	if v, ok := m["url"]; ok {
		switch v.(type) {
		case string:
			e.Url = v.(string)
		default:
			return ent, fmt.Errorf("erroneus url type, expected string, found: %T", v)
		}
	}
	if v, ok := m["paths"]; ok {
		switch v.(type) {
		case []string:
			e.Paths = v.([]string)
		default:
			return ent, fmt.Errorf("erroneus paths type, expected []string, found: %T", v)
		}
	}
	return e, err
}

func (e *UrlFinding) Validate() []validator.FieldError {
	return Validate(e)
}

func (e *EmailFinding) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"email": e.Email,
		"paths": e.Paths,
	}
}

func (e *EmailFinding) FromMap(m map[string]interface{}) (ent Entity, err error) {
	if v, ok := m["email"]; ok {
		switch v.(type) {
		case string:
			e.Email = v.(string)
		default:
			return ent, fmt.Errorf("erroneus email type, expected string, found: %T", v)
		}
	}
	if v, ok := m["paths"]; ok {
		switch v.(type) {
		case []string:
			e.Paths = v.([]string)
		default:
			return ent, fmt.Errorf("erroneus paths type, expected []string, found: %T", v)
		}
	}
	return e, err
}

func (e *EmailFinding) Validate() []validator.FieldError {
	return Validate(e)
}

func (e *CodeAnalysis) ToMap() map[string]interface{} {
	var codes []map[string]interface{}
	for _, v := range e.Codes {
		codes = append(codes, v.ToMap())
	}
	var apis []map[string]interface{}
	for _, v := range e.Apis {
		apis = append(apis, v.ToMap())
	}
	var urls []map[string]interface{}
	for _, v := range e.Urls {
		urls = append(urls, v.ToMap())
	}
	var emails []map[string]interface{}
	for _, v := range e.Emails {
		emails = append(emails, v.ToMap())
	}
	return map[string]interface{}{
		"codes":       codes,
		"apis":        apis,
		"urls":        urls,
		"emails":      emails,
		"bad_domains": e.BadDomains,
	}
}

func (e *CodeAnalysis) FromMap(m map[string]interface{}) (ent Entity, err error) {
	var (
		codes  []CodeFinding
		apis   []ApiFinding
		urls   []UrlFinding
		emails []EmailFinding
	)
	if v, ok := m["codes"]; ok {
		for _, m := range v.([]map[string]interface{}) {
			code, err := (&CodeFinding{}).FromMap(m)
			if err != nil {
				return ent, err
			}
			codes = append(codes, *code.(*CodeFinding))
		}
		e.Codes = codes
	}
	if v, ok := m["apis"]; ok {
		for _, m := range v.([]map[string]interface{}) {
			api, err := (&ApiFinding{}).FromMap(m)
			if err != nil {
				return ent, err
			}
			apis = append(apis, *api.(*ApiFinding))
		}
		e.Apis = apis
	}
	if v, ok := m["urls"]; ok {
		for _, m := range v.([]map[string]interface{}) {
			url, err := (&UrlFinding{}).FromMap(m)
			if err != nil {
				return ent, err
			}
			urls = append(urls, *url.(*UrlFinding))
		}
		e.Urls = urls
	}
	if v, ok := m["emails"]; ok {
		for _, m := range v.([]map[string]interface{}) {
			email, err := (&EmailFinding{}).FromMap(m)
			if err != nil {
				return ent, err
			}
			emails = append(emails, *email.(*EmailFinding))
		}
		e.Emails = emails
	}
	if v, ok := m["bad_domains"]; ok {
		switch v.(type) {
		case []string:
			e.BadDomains = v.([]string)
		default:
			return ent, fmt.Errorf("erroneus bad_domains type, expected []string, found: %T", v)
		}
	}
	return e, err
}

func (e *CodeAnalysis) Validate() []validator.FieldError {
	return Validate(e)
}
