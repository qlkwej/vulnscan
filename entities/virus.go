package entities

import (
	"fmt"
	"gopkg.in/go-playground/validator.v9"
)

type (
	VirusResponse struct {
		ResponseCode int    `json:"response_code"`
		VerboseMsg   string `json:"verbose_msg" validate:"required"`
		Resource     string `json:"resource" validate:"required"`
		ScanId       string `json:"scan_id" validate:"required"`
		Sha256       string `json:"sha256" validate:"required"`
		Permalink    string `json:"permalink" validate:"required"`
	}

	VirusScan struct {
		Detected bool   `json:"detected" validate:"required"`
		Version  string `json:"version" validate:"required"`
		Result   string `json:"result" validate:"required"`
		Update   string `json:"update" validate:"required"`
	}

	VirusReport struct {
		VirusResponse
		Md5       string               `json:"md5" validate:"required"`
		Sha1      string               `json:"sha1" validate:"required"`
		ScanDate  string               `json:"scan_date" validate:"required"`
		Positives int                  `json:"positives"`
		Total     int                  `json:"total" validate:"required"`
		Scans     map[string]VirusScan `json:"scans" validate:"required"`
	}

	VirusAnalysis struct {
		HasReport bool          `json:"has_report"`
		Response  VirusResponse `json:"response" validate:"required"`
		Report    VirusReport   `json:"report" validate:"structonly"`
	}
)

func (e *VirusResponse) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"response_code": e.ResponseCode,
		"verbose_msg":   e.VerboseMsg,
		"resource":      e.Resource,
		"scan_id":       e.ScanId,
		"sha256":        e.Sha256,
		"permalink":     e.Permalink,
	}
}

func (e *VirusResponse) FromMap(m map[string]interface{}) (ent Entity, err error) {
	if v, ok := m["response_code"]; ok {
		switch v.(type) {
		case int:
			e.ResponseCode = v.(int)
		case int8:
			e.ResponseCode = int(v.(int8))
		case int16:
			e.ResponseCode = int(v.(int16))
		case int32:
			e.ResponseCode = int(v.(int32))
		case int64:
			e.ResponseCode = int(v.(int64))
		case uint:
			e.ResponseCode = int(v.(uint))
		case uint8:
			e.ResponseCode = int(v.(int8))
		case uint16:
			e.ResponseCode = int(v.(int16))
		case uint32:
			e.ResponseCode = int(v.(int32))
		case uint64:
			e.ResponseCode = int(v.(int64))
		case float32:
			e.ResponseCode = int(v.(float32))
		case float64:
			e.ResponseCode = int(v.(float64))
		default:
			return ent, fmt.Errorf("erroneus response_code type, expected int/uint, found: %T", v)
		}
	}
	if v, ok := m["verbose_msg"]; ok {
		switch v.(type) {
		case string:
			e.VerboseMsg = v.(string)
		default:
			return ent, fmt.Errorf("erroneus verbose_mode type, expected string, found: %T", v)
		}
	}
	if v, ok := m["resource"]; ok {
		switch v.(type) {
		case string:
			e.Resource = v.(string)
		default:
			return ent, fmt.Errorf("erroneus resource type, expected string, found: %T", v)
		}
	}
	if v, ok := m["scan_id"]; ok {
		switch v.(type) {
		case string:
			e.ScanId = v.(string)
		default:
			return ent, fmt.Errorf("erroneus scan_id type, expected string, found: %T", v)
		}
	}
	if v, ok := m["sha256"]; ok {
		switch v.(type) {
		case string:
			e.Sha256 = v.(string)
		default:
			return ent, fmt.Errorf("erroneus sha256 type, expected string, found: %T", v)
		}
	}
	if v, ok := m["permalink"]; ok {
		switch v.(type) {
		case string:
			e.Permalink = v.(string)
		default:
			return ent, fmt.Errorf("erroneus permalink type, expected string, found: %T", v)
		}
	}
	return e, err
}

func (e *VirusResponse) Validate() []validator.FieldError {
	return Validate(e)
}

func (e *VirusScan) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"detected": e.Detected,
		"version":  e.Version,
		"update":   e.Update,
		"result":   e.Result,
	}
}

func (e *VirusScan) FromMap(m map[string]interface{}) (ent Entity, err error) {
	if v, ok := m["detected"]; ok {
		switch v.(type) {
		case bool:
			e.Detected = v.(bool)
		default:
			return ent, fmt.Errorf("erroneus permalink type, expected string, found: %T", v)
		}
	}
	if v, ok := m["version"]; ok {
		switch v.(type) {
		case string:
			e.Version = v.(string)
		case nil:
			e.Version = ""
		default:
			return ent, fmt.Errorf("erroneus version type, expected string, found: %T", v)
		}
	}
	if v, ok := m["update"]; ok {
		switch v.(type) {
		case string:
			e.Update = v.(string)
		case nil:
			e.Update = ""
		default:
			return ent, fmt.Errorf("erroneus update type, expected string, found: %T", v)
		}
	}
	if v, ok := m["result"]; ok {
		switch v.(type) {
		case string:
			e.Result = v.(string)
		case nil:
			e.Update = ""
		default:
			return ent, fmt.Errorf("erroneus result type, expected string, found: %T", v)
		}
	}

	return e, err
}

func (e *VirusScan) Validate() []validator.FieldError {
	return Validate(e)
}

func (e *VirusReport) ToMap() map[string]interface{} {
	vr := e.VirusResponse.ToMap()
	vr["md5"] = e.Md5
	vr["sha1"] = e.Sha1
	vr["scan_date"] = e.ScanDate
	vr["positives"] = e.Positives
	vr["total"] = e.Total
	scans := map[string]interface{}{}
	for k, s := range e.Scans {
		scans[k] = s.ToMap()
	}
	vr["scans"] = scans
	return vr
}

func (e *VirusReport) FromMap(m map[string]interface{}) (ent Entity, err error) {
	vr, err := (&VirusResponse{}).FromMap(m)
	if err != nil {
		return ent, err
	}
	e.VirusResponse = *vr.(*VirusResponse)
	if v, ok := m["md5"]; ok {
		switch v.(type) {
		case string:
			e.Md5 = v.(string)
		default:
			return ent, fmt.Errorf("erroneus md_5 type, expected string, found: %T", v)
		}
	}
	if v, ok := m["sha1"]; ok {
		switch v.(type) {
		case string:
			e.Sha1 = v.(string)
		default:
			return ent, fmt.Errorf("erroneus sha1 type, expected string, found: %T", v)
		}
	}
	if v, ok := m["scan_date"]; ok {
		switch v.(type) {
		case string:
			e.ScanDate = v.(string)
		default:
			return ent, fmt.Errorf("erroneus scan_date type, expected string, found: %T", v)
		}
	}
	if v, ok := m["positives"]; ok {
		switch v.(type) {
		case int:
			e.Positives = v.(int)
		case int8:
			e.Positives = int(v.(int8))
		case int16:
			e.Positives = int(v.(int16))
		case int32:
			e.Positives = int(v.(int32))
		case int64:
			e.Positives = int(v.(int64))
		case uint:
			e.Positives = int(v.(uint))
		case uint8:
			e.Positives = int(v.(int8))
		case uint16:
			e.Positives = int(v.(int16))
		case uint32:
			e.Positives = int(v.(int32))
		case uint64:
			e.Positives = int(v.(int64))
		case float32:
			e.Positives = int(v.(float32))
		case float64:
			e.Positives = int(v.(float64))
		default:
			return ent, fmt.Errorf("erroneus positives type, expected int/uint, found: %T", v)
		}

	}
	if v, ok := m["total"]; ok {
		switch v.(type) {
		case int:
			e.Total = v.(int)
		case int8:
			e.Total = int(v.(int8))
		case int16:
			e.Total = int(v.(int16))
		case int32:
			e.Total = int(v.(int32))
		case int64:
			e.Total = int(v.(int64))
		case uint:
			e.Total = int(v.(uint))
		case uint8:
			e.Total = int(v.(int8))
		case uint16:
			e.Total = int(v.(int16))
		case uint32:
			e.Total = int(v.(int32))
		case uint64:
			e.Total = int(v.(int64))
		case float32:
			e.Total = int(v.(float32))
		case float64:
			e.Total = int(v.(float64))
		default:
			return ent, fmt.Errorf("erroneus total type, expected int/uint, found: %T", v)
		}
	}
	if v, ok := m["scans"]; ok {
		switch v.(type) {
		case map[string]interface{}:
			scans := map[string]VirusScan{}
			for n, vl := range v.(map[string]interface{}) {
				switch vl.(type) {
				case map[string]interface{}:
					vs, err := (&VirusScan{}).FromMap(vl.(map[string]interface{}))
					if err != nil {
						return ent, err
					}
					scans[n] = *vs.(*VirusScan)
				default:
					return ent, fmt.Errorf("erroneus scan type, expected map[string]interface{}, found: %T", vl)
				}
			}
			e.Scans = scans
		default:
			return ent, fmt.Errorf("erroneus scans type, expected map[string]interface{}, found: %T", v)
		}
	}
	return e, err
}

func (e *VirusReport) Validate() []validator.FieldError {
	return Validate(e)
}

func (e *VirusAnalysis) ToMap() map[string]interface{} {
	if e.HasReport {
		return e.Report.ToMap()
	}
	return e.Response.ToMap()
}

func (e *VirusAnalysis) FromMap(m map[string]interface{}) (ent Entity, err error) {
	response, err := e.Response.FromMap(m)
	if err != nil {
		return ent, err
	}
	e.Response = *response.(*VirusResponse)
	if _, ok := m["scan_date"]; ok {
		e.HasReport = true
		report, err := e.Report.FromMap(m)
		if err != nil {
			return ent, err
		}
		e.Report = *report.(*VirusReport)
	}
	return e, err
}

func (e *VirusAnalysis) Validate() []validator.FieldError {
	var errors []validator.FieldError
	if e.HasReport {
		errors = append(errors, Validate(&e.Report)...)
	}
	errors = append(errors, Validate(e)...)
	return errors
}
