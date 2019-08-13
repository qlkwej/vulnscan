package entities

import (
	"fmt"
	"gopkg.in/go-playground/validator.v9"
)

type (
	VirusResponse struct {
		ResponseCode 	int    `json:"response_code"`
		VerboseMsg 		string `json:"verbose_msg"`
		Resource 		string `json:"resource"`
		ScanId 			string `json:"scan_id"`
		Sha256 			string `json:"sha_256"`
		PermaLink 		string `json:"perma_link"`
	}

	VirusScan struct {
		Detected 	bool 	`json:"detected"`
		Version 	string 	`json:"version"`
		Result 		string 	`json:"result"`
		Update 		string 	`json:"update"`
	}

	VirusAnalysis struct {
		VirusResponse
		Md5 		string 				 `json:"md_5"`
		Sha1 		string 				 `json:"sha_1"`
		ScanDate 	string 				 `json:"scan_date"`
		Positives 	int 				 `json:"positives"`
		Total 		int 				 `json:"total"`
		Scans 		map[string]VirusScan `json:"scans"`
	}
)

func (e *VirusResponse) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"response_code": e.ResponseCode,
		"verbose_msg": e.VerboseMsg,
		"resource": e.Resource,
		"scan_id": e.ScanId,
		"sha_256": e.Sha256,
		"perma_link": e.PermaLink,
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
		default:
			return ent, fmt.Errorf("erroneus response_code type, expected int/uint, found: %T", v)
		}
	}
	if v, ok := m["verbose_mode"]; ok {
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
	if v, ok := m["sha_256"]; ok {
		switch v.(type) {
		case string:
			e.Sha256 = v.(string)
		default:
			return ent, fmt.Errorf("erroneus sha_256 type, expected string, found: %T", v)
		}
	}
	if v, ok := m["perma_link"]; ok {
		switch v.(type) {
		case string:
			e.PermaLink = v.(string)
		default:
			return ent, fmt.Errorf("erroneus perma_link type, expected string, found: %T", v)
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
		"version": e.Version,
		"update": e.Update,
		"result": e.Result,
	}
}

func (e *VirusScan) FromMap(m map[string]interface{}) (ent Entity, err error) {
	if v, ok := m["detected"]; ok {
		switch v.(type) {
		case bool:
			e.Detected = v.(bool)
		default:
			return ent, fmt.Errorf("erroneus perma_link type, expected string, found: %T", v)
		}
	}
	if v, ok := m["version"]; ok {
		switch v.(type) {
		case string:
			e.Version = v.(string)
		default:
			return ent, fmt.Errorf("erroneus version type, expected string, found: %T", v)
		}
	}
	if v, ok := m["update"]; ok {
		switch v.(type) {
		case string:
			e.Update = v.(string)
		default:
			return ent, fmt.Errorf("erroneus update type, expected string, found: %T", v)
		}
	}
	if v, ok := m["result"]; ok {
		switch v.(type) {
		case string:
			e.Result = v.(string)
		default:
			return ent, fmt.Errorf("erroneus result type, expected string, found: %T", v)
		}
	}
	return e, err
}

func (e *VirusScan) Validate() []validator.FieldError {
	return Validate(e)
}

func (e *VirusAnalysis) ToMap() map[string]interface{} {
	vr := e.VirusResponse.ToMap()
	vr["md_5"] = e.Md5
	vr["sha_1"] = e.Sha1
	vr["scan_date"] = e.ScanDate
	vr["positives"] = e.Positives
	vr["total"] = e.Total
	scans := map[string]map[string]interface{}{}
	for k, s := range e.Scans {
		scans[k] = s.ToMap()
	}
	vr["scans"] = scans
	return vr
}

func (e *VirusAnalysis) FromMap(m map[string]interface{}) (ent Entity, err error) {
	vr, err := (&VirusResponse{}).FromMap(m)
	if err != nil {
		return ent, err
	}
	e.VirusResponse = *vr.(*VirusResponse)
	if v, ok := m["md_5"]; ok {
		switch v.(type) {
		case string:
			e.Md5 = v.(string)
		default:
			return ent, fmt.Errorf("erroneus md_5 type, expected string, found: %T", v)
		}
	}
	if v, ok := m["sha_1"]; ok {
		switch v.(type) {
		case string:
			e.Sha1 = v.(string)
		default:
			return ent, fmt.Errorf("erroneus sha_1 type, expected string, found: %T", v)
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
		default:
			return ent, fmt.Errorf("erroneus total type, expected int/uint, found: %T", v)
		}
	}
	if v, ok := m["scans"]; ok {
		switch v.(type) {
		case map[string]map[string]interface{}:
			scans := map[string]VirusScan{}
			for n, v := range v.(map[string]map[string]interface{}) {
				vs, err := (&VirusScan{}).FromMap(v)
				if err != nil {
					return ent, err
				}
				scans[n] = *vs.(*VirusScan)
			}
		default:
			return ent, fmt.Errorf("erroneus scans type, expected int/uint, found: %T", v)
		}
	}
	return e, err
}

func (e *VirusAnalysis) Validate() []validator.FieldError {
	return Validate(e)
}


