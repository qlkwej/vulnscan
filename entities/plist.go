package entities

import (
	"fmt"
	"gopkg.in/go-playground/validator.v9"
)

type (
	BundleUrlType struct {
		Name    string   `json:"name" validate:"required"`
		Schemas []string `json:"schemas" validate:"min=1"`
	}

	Permission struct {
		Name        string `json:"name" validate:"min=1"`
		Description string `json:"description" validate:"min=1"`
		Reason      string `json:"reason" validate:"min=1"`
	}

	InsecureConnections struct {
		AllowArbitraryLoads bool     `json:"allow_arbitrary_loads"`
		Domains             []string `json:"domains"`
	}

	PListAnalysis struct {
		Xml                      string              `json:"xml" validate:"min=1"`
		BinName                  string              `json:"bin_name" validate:"min=1"`
		Bin                      string              `json:"bin" validate:"min=1"`
		Id                       string              `json:"id" validate:"min=1"`
		Build                    string              `json:"build" validate:"min=1"`
		SDK                      string              `json:"sdk" validate:"min=1"`
		Platform                 string              `json:"platform" validate:"min=1"`
		MinimumVersion           string              `json:"minimum_version" validate:"min=1"`
		BundleName               string              `json:"bundle_name" validate:"min=1"`
		BundleVersionName        string              `json:"bundle_version_name" validate:"min=1"`
		BundleSupportedPlatforms []string            `json:"bundle_supported_platforms" validate:"min=1"`
		BundleLocalizations      []string            `json:"bundle_localizations" validate:"min=1"`
		BundleUrlTypes           []BundleUrlType     `json:"bundle_url_types" validate:"required"`
		Permissions              []Permission        `json:"permissions" validate:"required"`
		InsecureConnections      InsecureConnections `json:"insecure_connections" validate:"required"`
	}
)

func (e *BundleUrlType) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"name":    e.Name,
		"schemas": e.Schemas,
	}
}

func (e *BundleUrlType) FromMap(m map[string]interface{}) (ent Entity, err error) {
	if v, ok := m["name"]; ok {
		switch v.(type) {
		case string:
			e.Name = v.(string)
		default:
			return ent, fmt.Errorf("erroneus name type, expected string, found: %T", v)
		}
	}
	if v, ok := m["schemas"]; ok {
		switch v.(type) {
		case []string:
			e.Schemas = v.([]string)
		default:
			return ent, fmt.Errorf("erroneus schemas type, expected string, found: %T", v)
		}
	}
	return e, err
}

func (e *BundleUrlType) Validate() []validator.FieldError {
	return Validate(e)
}

func (e *Permission) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"name":        e.Name,
		"description": e.Description,
		"reason":      e.Reason,
	}
}

func (e *Permission) FromMap(m map[string]interface{}) (ent Entity, err error) {
	if v, ok := m["name"]; ok {
		switch v.(type) {
		case string:
			e.Name = v.(string)
		default:
			return ent, fmt.Errorf("erroneus name type, expected string, found: %T", v)
		}
	}
	if v, ok := m["description"]; ok {
		switch v.(type) {
		case string:
			e.Description = v.(string)
		default:
			return ent, fmt.Errorf("erroneus description type, expected string, found: %T", v)
		}
	}
	if v, ok := m["reason"]; ok {
		switch v.(type) {
		case string:
			e.Reason = v.(string)
		default:
			return ent, fmt.Errorf("erroneus reason type, expected string, found: %T", v)
		}
	}
	return e, err
}

func (e *Permission) Validate() []validator.FieldError {
	return Validate(e)
}

func (e *InsecureConnections) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"allow_arbitrary_loads": e.AllowArbitraryLoads,
		"domains":               e.Domains,
	}
}

func (e *InsecureConnections) FromMap(m map[string]interface{}) (ent Entity, err error) {
	if v, ok := m["allow_arbitrary_loads"]; ok {
		switch v.(type) {
		case bool:
			e.AllowArbitraryLoads = v.(bool)
		default:
			return ent, fmt.Errorf("erroneus allow_arbitrary_loads type, expected string, found: %T", v)
		}
	}
	if v, ok := m["domains"]; ok {
		switch v.(type) {
		case []string:
			e.Domains = v.([]string)
		default:
			return ent, fmt.Errorf("erroneus domains type, expected string, found: %T", v)
		}
	}
	return e, err
}

func (e *InsecureConnections) Validate() []validator.FieldError {
	return Validate(e)
}

func (e *PListAnalysis) ToMap() map[string]interface{} {
	m := map[string]interface{}{
		"xml":                        e.Xml,
		"bin_name":                   e.BinName,
		"bin":                        e.Bin,
		"id":                         e.Id,
		"build":                      e.Build,
		"sdk":                        e.SDK,
		"platform":                   e.Platform,
		"minimum_version":            e.MinimumVersion,
		"bundle_name":                e.BundleName,
		"bundle_version_name":        e.BundleVersionName,
		"bundle_supported_platforms": e.BundleSupportedPlatforms,
		"bundle_localizations":       e.BundleLocalizations,
		"bundle_url_types":           []map[string]interface{}{},
		"permissions":                []map[string]interface{}{},
		"insecure_connections":       e.InsecureConnections.ToMap(),
	}
	for _, bundle := range e.BundleUrlTypes {
		m["bundle_url_types"] = append(m["bundle_url_types"].([]map[string]interface{}), bundle.ToMap())
	}
	for _, bundle := range e.Permissions {
		m["permissions"] = append(m["permissions"].([]map[string]interface{}), bundle.ToMap())
	}
	return m
}

func (e *PListAnalysis) FromMap(m map[string]interface{}) (ent Entity, err error) {
	if v, ok := m["xml"]; ok {
		switch v.(type) {
		case string:
			e.Xml = v.(string)
		default:
			return ent, fmt.Errorf("erroneus xml type, expected string, found: %T", v)
		}
	}
	if v, ok := m["bin_name"]; ok {
		switch v.(type) {
		case string:
			e.BinName = v.(string)
		default:
			return ent, fmt.Errorf("erroneus bin_name type, expected string, found: %T", v)
		}
	}
	if v, ok := m["bin"]; ok {
		switch v.(type) {
		case string:
			e.Bin = v.(string)
		default:
			return ent, fmt.Errorf("erroneus bin type, expected string, found: %T", v)
		}
	}
	if v, ok := m["id"]; ok {
		switch v.(type) {
		case string:
			e.Id = v.(string)
		default:
			return ent, fmt.Errorf("erroneus id type, expected string, found: %T", v)
		}
	}
	if v, ok := m["build"]; ok {
		switch v.(type) {
		case string:
			e.Build = v.(string)
		default:
			return ent, fmt.Errorf("erroneus build type, expected string, found: %T", v)
		}
	}
	if v, ok := m["sdk"]; ok {
		switch v.(type) {
		case string:
			e.SDK = v.(string)
		default:
			return ent, fmt.Errorf("erroneus sdk type, expected string, found: %T", v)
		}
	}
	if v, ok := m["platform"]; ok {
		switch v.(type) {
		case string:
			e.Platform = v.(string)
		default:
			return ent, fmt.Errorf("erroneus platform type, expected string, found: %T", v)
		}
	}
	if v, ok := m["minimum_version"]; ok {
		switch v.(type) {
		case string:
			e.MinimumVersion = v.(string)
		default:
			return ent, fmt.Errorf("erroneus minimum_version type, expected string, found: %T", v)
		}
	}
	if v, ok := m["bundle_name"]; ok {
		switch v.(type) {
		case string:
			e.BundleName = v.(string)
		default:
			return ent, fmt.Errorf("erroneus bundle_name type, expected string, found: %T", v)
		}
	}
	if v, ok := m["bundle_version_name"]; ok {
		switch v.(type) {
		case string:
			e.BundleVersionName = v.(string)
		default:
			return ent, fmt.Errorf("erroneus bundle_version_name type, expected string, found: %T", v)
		}
	}
	if v, ok := m["bundle_supported_platforms"]; ok {
		switch v.(type) {
		case []string:
			e.BundleSupportedPlatforms = v.([]string)
		default:
			return ent, fmt.Errorf("erroneus bundle_supported_platforms type, expected string, found: %T", v)
		}
	}
	if v, ok := m["bundle_localizations"]; ok {
		switch v.(type) {
		case []string:
			e.BundleLocalizations = v.([]string)
		default:
			return ent, fmt.Errorf("erroneus bundle_localizations type, expected string, found: %T", v)
		}
	}
	if v, ok := m["bundle_url_types"]; ok {
		switch v.(type) {
		case []map[string]interface{}:
			for _, i := range v.([]map[string]interface{}) {
				but, err := (&BundleUrlType{}).FromMap(i)
				if err != nil {
					return ent, err
				}
				e.BundleUrlTypes = append(e.BundleUrlTypes, *(but.(*BundleUrlType)))
			}
		default:
			return ent, fmt.Errorf("erroneus bundle_url_types type, expected string, found: %T", v)
		}
	}
	if v, ok := m["permissions"]; ok {
		switch v.(type) {
		case []map[string]interface{}:
			for _, i := range v.([]map[string]interface{}) {
				p, err := (&Permission{}).FromMap(i)
				if err != nil {
					return ent, err
				}
				e.Permissions = append(e.Permissions, *(p.(*Permission)))
			}
		default:
			return ent, fmt.Errorf("erroneus permissions type, expected string, found: %T", v)
		}
	}
	if v, ok := m["insecure_connections"]; ok {
		switch v.(type) {
		case map[string]interface{}:
			i, err := (&InsecureConnections{}).FromMap(v.(map[string]interface{}))
			if err != nil {
				return ent, err
			}
			e.InsecureConnections = *i.(*InsecureConnections)
		default:
			return ent, fmt.Errorf("erroneus insecure_connections type, expected string, found: %T", v)
		}
	}
	return e, err
}

func (e *PListAnalysis) Validate() []validator.FieldError {
	return Validate(e)
}
