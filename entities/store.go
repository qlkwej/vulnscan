package entities

import (
	"fmt"
	"gopkg.in/go-playground/validator.v9"
)

type (
	StoreResult struct {
		Features         	[]string 	`json:"features"`
		IconUrl512       	string   	`json:"artworkUrl512"`
		IconUrl100       	string   	`json:"artworkUrl100"`
		IconUrl60        	string   	`json:"artworkUrl60"`
		DeveloperId      	int      	`json:"artistId"`
		DeveloperName    	string   	`json:"artistName"`
		DeveloperUrl     	string   	`json:"artistViewUrl"`
		DeveloperWebsite 	string   	`json:"sellerUrl"`
		SupportedDevices 	[]string 	`json:"supportedDevices"`
		Title            	string   	`json:"trackName"`
		AppId            	string   	`json:"bundleId"`
		Categories       	[]string 	`json:"genres"`
		Description      	string   	`json:"description"`
		Price            	float32  	`json:"price"`
		Url        			string   	`json:"trackViewUrl"`
		Score            	float32  	`json:"averageUserRating"`
	}

	StoreAnalysis struct {
		Count 	int 			`json:"count"`
		Results []StoreResult 	`json:"results"`
	}
)

func (e *StoreResult) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"features":         	e.Features,
		"icon_url_512": 		e.IconUrl512,
		"icon_url_100":			e.IconUrl100,
		"icon_url_60": 			e.IconUrl60,
		"developer_id": 		e.DeveloperId,
		"developer_name":		e.DeveloperName,
		"developer_url": 		e.DeveloperUrl,
		"developer_website":	e.DeveloperWebsite,
		"supported_devices": 	e.SupportedDevices,
		"title":				e.Title,
		"app_id":				e.AppId,
		"categories":			e.Categories,
		"description": 			e.Description,
		"price":				e.Price,
		"url":					e.Url,
		"score":				e.Score,
	}
}

func (e *StoreResult) FromMap(m map[string]interface{}) (ent Entity, err error) {
	if v, ok := m["features"]; ok {
		switch v.(type) {
		case []string:
			e.Features = v.([]string)
		default:
			return ent, fmt.Errorf("erroneus features type, expected []string, found: %T", v)
		}
	}
	if v, ok := m["artworkUrl512"]; ok {
		switch v.(type) {
		case string:
			e.IconUrl512 = v.(string)
		default:
			return ent, fmt.Errorf("erroneus icon url type, expected string, found: %T", v)
		}
	} else if v, ok := m["icon_url_512"]; ok {
		switch v.(type) {
		case string:
			e.IconUrl512 = v.(string)
		default:
			return ent, fmt.Errorf("erroneus icon url type, expected string, found: %T", v)
		}
	}
	if v, ok := m["artworkUrl100"]; ok {
		switch v.(type) {
		case string:
			e.IconUrl100 = v.(string)
		default:
			return ent, fmt.Errorf("erroneus icon url type, expected string, found: %T", v)
		}
	} else if v, ok := m["icon_url_100"]; ok {
		switch v.(type) {
		case string:
			e.IconUrl100 = v.(string)
		default:
			return ent, fmt.Errorf("erroneus icon url type, expected string, found: %T", v)
		}
	}
	if v, ok := m["artworkUrl60"]; ok {
		switch v.(type) {
		case string:
			e.IconUrl60 = v.(string)
		default:
			return ent, fmt.Errorf("erroneus icon url type, expected string, found: %T", v)
		}
	} else if v, ok := m["icon_url_60"]; ok {
		switch v.(type) {
		case string:
			e.IconUrl60 = v.(string)
		default:
			return ent, fmt.Errorf("erroneus icon url type, expected string, found: %T", v)
		}
	}
	if v, ok := m["artistId"]; ok {
		switch v.(type) {
		case int:
			e.DeveloperId = v.(int)
		case int8:
			e.DeveloperId = int(v.(int8))
		case int16:
			e.DeveloperId = int(v.(int16))
		case int32:
			e.DeveloperId = int(v.(int32))
		case int64:
			e.DeveloperId = int(v.(int64))
		case uint:
			e.DeveloperId = int(v.(uint))
		case uint8:
			e.DeveloperId = int(v.(int8))
		case uint16:
			e.DeveloperId = int(v.(int16))
		case uint32:
			e.DeveloperId = int(v.(int32))
		case uint64:
			e.DeveloperId = int(v.(int64))
		default:
			return ent, fmt.Errorf("erroneus developer id type, expected int/uint, found: %T", v)
		}
	} else if v, ok := m["developer_id"]; ok {
		switch v.(type) {
		case int:
			e.DeveloperId = v.(int)
		case int8:
			e.DeveloperId = int(v.(int8))
		case int16:
			e.DeveloperId = int(v.(int16))
		case int32:
			e.DeveloperId = int(v.(int32))
		case int64:
			e.DeveloperId = int(v.(int64))
		case uint:
			e.DeveloperId = int(v.(uint))
		case uint8:
			e.DeveloperId = int(v.(int8))
		case uint16:
			e.DeveloperId = int(v.(int16))
		case uint32:
			e.DeveloperId = int(v.(int32))
		case uint64:
			e.DeveloperId = int(v.(int64))
		default:
			return ent, fmt.Errorf("erroneus developer id type, expected int/uint, found: %T", v)
		}
	}
	if v, ok := m["artistName"]; ok {
		switch v.(type) {
		case string:
			e.DeveloperName = v.(string)
		default:
			return ent, fmt.Errorf("erroneus developer name type, expected string, found: %T", v)
		}
	} else if v, ok := m["developer_name"]; ok {
		switch v.(type) {
		case string:
			e.DeveloperName = v.(string)
		default:
			return ent, fmt.Errorf("erroneus developer name type, expected string, found: %T", v)
		}
	}
	if v, ok := m["artistViewUrl"]; ok {
		switch v.(type) {
		case string:
			e.DeveloperUrl = v.(string)
		default:
			return ent, fmt.Errorf("erroneus developer url type, expected string, found: %T", v)
		}
	} else if v, ok := m["developer_url"]; ok {
		switch v.(type) {
		case string:
			e.DeveloperUrl = v.(string)
		default:
			return ent, fmt.Errorf("erroneus developer url type, expected string, found: %T", v)
		}
	}
	if v, ok := m["sellerUrl"]; ok {
		switch v.(type) {
		case string:
			e.DeveloperWebsite = v.(string)
		default:
			return ent, fmt.Errorf("erroneus developer website type, expected string, found: %T", v)
		}
	} else if v, ok := m["developer_website"]; ok {
		switch v.(type) {
		case string:
			e.DeveloperWebsite = v.(string)
		default:
			return ent, fmt.Errorf("erroneus developer website type, expected string, found: %T", v)
		}
	}
	if v, ok := m["supportedDevices"]; ok {
		switch v.(type) {
		case []string:
			e.SupportedDevices = v.([]string)
		default:
			return ent, fmt.Errorf("erroneus supported devices type, expected []string, found: %T", v)
		}
	} else if v, ok := m["supported_devices"]; ok {
		switch v.(type) {
		case []string:
			e.SupportedDevices = v.([]string)
		default:
			return ent, fmt.Errorf("erroneus supported devices type, expected []string, found: %T", v)
		}
	}
	if v, ok := m["trackName"]; ok {
		switch v.(type) {
		case string:
			e.AppId = v.(string)
		default:
			return ent, fmt.Errorf("erroneus app id type, expected string, found: %T", v)
		}
	} else if v, ok := m["title"]; ok {
		switch v.(type) {
		case string:
			e.Title = v.(string)
		default:
			return ent, fmt.Errorf("erroneus title type, expected string, found: %T", v)
		}
	}
	if v, ok := m["bundleId"]; ok {
		switch v.(type) {
		case string:
			e.AppId = v.(string)
		default:
			return ent, fmt.Errorf("erroneus app id type, expected string, found: %T", v)
		}
	} else if v, ok := m["app_id"]; ok {
		switch v.(type) {
		case string:
			e.AppId = v.(string)
		default:
			return ent, fmt.Errorf("erroneus app id type, expected string, found: %T", v)
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
	if v, ok := m["genres"]; ok {
		switch v.(type) {
		case []string:
			e.Categories = v.([]string)
		default:
			return ent, fmt.Errorf("erroneus categories type, expected []string, found: %T", v)
		}
	} else if v, ok := m["categories"]; ok {
		switch v.(type) {
		case []string:
			e.Categories = v.([]string)
		default:
			return ent, fmt.Errorf("erroneus categories type, expected []string, found: %T", v)
		}
	}
	if v, ok := m["price"]; ok {
		switch v.(type) {
		case float32:
			e.Price = v.(float32)
		case float64:
			e.Price = float32(v.(float64))
		case int:
			e.Price = float32(v.(int))
		case int8:
			e.Price = float32(v.(int8))
		case int16:
			e.Price = float32(v.(int16))
		case int32:
			e.Price = float32(v.(int32))
		case int64:
			e.Price = float32(v.(int64))
		default:
			return ent, fmt.Errorf("erroneus price type, expected float/int, found: %T", v)
		}
	}
	if v, ok := m["trackViewUrl"]; ok {
		switch v.(type) {
		case string:
			e.Url = v.(string)
		default:
			return ent, fmt.Errorf("erroneus url type, expected string, found: %T", v)
		}
	} else if v, ok := m["url"]; ok {
		switch v.(type) {
		case string:
			e.Url = v.(string)
		default:
			return ent, fmt.Errorf("erroneus url type, expected string, found: %T", v)
		}
	}
	if v, ok := m["averageUserRating"]; ok {
		switch v.(type) {
		case float32:
			e.Score = v.(float32)
		case float64:
			e.Score = float32(v.(float64))
		case int:
			e.Score = float32(v.(int))
		case int8:
			e.Score = float32(v.(int8))
		case int16:
			e.Score = float32(v.(int16))
		case int32:
			e.Score = float32(v.(int32))
		case int64:
			e.Score = float32(v.(int64))
		default:
			return ent, fmt.Errorf("erroneus score type, expected float/int, found: %T", v)
		}
	} else if v, ok := m["score"]; ok {
		switch v.(type) {
		case float32:
			e.Score = v.(float32)
		case float64:
			e.Score = float32(v.(float64))
		case int:
			e.Score = float32(v.(int))
		case int8:
			e.Score = float32(v.(int8))
		case int16:
			e.Score = float32(v.(int16))
		case int32:
			e.Score = float32(v.(int32))
		case int64:
			e.Score = float32(v.(int64))
		default:
			return ent, fmt.Errorf("erroneus score type, expected float/int, found: %T", v)
		}
	}
	return e, err
}

func (e *StoreResult) Validate() []validator.FieldError {
	return Validate(e)
}

func (e *StoreAnalysis) ToMap() map[string]interface{} {
	var results []map[string]interface{}
	for _, r := range e.Results {
		results = append(results, r.ToMap())
	}
	return map[string]interface{}{
		"count": e.Count,
		"results": results
	}
}

func (e *StoreAnalysis) FromMap(m map[string]interface{}) (ent Entity, err error) {
	if v, ok :=  m["count"]; ok {
		switch v.(type) {
		case int:
			e.Count = v.(int)
		case int8:
			e.Count = int(v.(int8))
		case int16:
			e.Count = int(v.(int16))
		case int32:
			e.Count = int(v.(int32))
		case int64:
			e.Count = int(v.(int64))
		case uint:
			e.Count = int(v.(uint))
		case uint8:
			e.Count = int(v.(int8))
		case uint16:
			e.Count = int(v.(int16))
		case uint32:
			e.Count = int(v.(int32))
		case uint64:
			e.Count = int(v.(int64))
		default:
			return ent, fmt.Errorf("erroneus count type, expected int/uint, found: %T", v)
		}
	}
	if v, ok :=  m["results"]; ok {
		switch v.(type) {
		case []map[string]interface{}:
			for _, m := range v.([]map[string]interface{}) {
				r, err := (&StoreResult{}).FromMap(m)
				if err != nil {
					return ent, err
				}
				e.Results = append(e.Results, *r.(*StoreResult))
			}
		default:
			return ent, fmt.Errorf("erroneus results type, expected []map[string]interface{}, found: %T", v)
		}
	}
	return e, err
}

func (e *StoreAnalysis) Validate() []validator.FieldError {
	return Validate(e)
}



