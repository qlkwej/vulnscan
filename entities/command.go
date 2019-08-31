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
		SourcePath	  string				 `json:"source_path"`
		AppName       string 				 `json:"app_name"`
		AppId         string 				 `json:"app_id"`
		Country       string 				 `json:"country" validate:"valid_country_codes"`
		VirusTotalKey string 				 `json:"virus_total_key"`
		Source        bool 					 `json:"source"`
		Analysis      map[AnalysisCheck]bool `json:"analysis" validate:"valid_analysis"`
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
	ItunesCountryCodes = map[string]string {
		"al": "Albania",
		"dz": "Algeria",
		"ao": "Angola",
		"ai": "Anguilla",
		"ag": "Antigua and Barbuda",
		"ar": "Argentina",
		"am": "Armenia",
		"au": "Australia",
		"at": "Austria",
		"az": "Azerbaijan",
		"bs": "Bahamas",
		"bh": "Bahrain",
		"bb": "Barbados",
		"by": "Belarus",
		"be": "Belgium",
		"bz": "Belize",
		"bj": "Benin",
		"bm": "Bermuda",
		"bt": "Bhutan",
		"bo": "Bolivia",
		"bw": "Botswana",
		"br": "Brazil",
		"vg": "British Virgin Islands",
		"bn": "Brunei Darussalam",
		"bg": "Bulgaria",
		"bf": "Burkina-Faso",
		"kh": "Cambodia",
		"ca": "Canada",
		"cv": "Cape Verde",
		"ky": "Cayman Islands",
		"td": "Chad",
		"cl": "Chile",
		"cn": "China",
		"co": "Colombia",
		"cr": "Costa Rica",
		"hr": "Croatia",
		"cy": "Cyprus",
		"cz": "Czech Republic",
		"cg": "Democratic Republic of the Congo",
		"dk": "Denmark",
		"dm": "Dominica",
		"do": "Dominican Republic",
		"ec": "Ecuador",
		"eg": "Egypt",
		"sv": "El Salvador",
		"ee": "Estonia",
		"fm": "Federated States of Micronesia",
		"fj": "Fiji",
		"fi": "Finland",
		"fr": "France",
		"gm": "Gambia",
		"de": "Germany",
		"gh": "Ghana",
		"gb": "Great Britain",
		"gr": "Greece",
		"gd": "Grenada",
		"gt": "Guatemala",
		"gw": "Guinea Bissau",
		"gy": "Guyana",
		"hn": "Honduras",
		"hk": "Hong Kong",
		"hu": "Hungaria",
		"is": "Iceland",
		"in": "India",
		"id": "Indonesia",
		"ie": "Ireland",
		"il": "Israel",
		"it": "Italy",
		"jm": "Jamaica",
		"jp": "Japan",
		"jo": "Jordan",
		"kz": "Kazakhstan",
		"ke": "Kenya",
		"kg": "Krygyzstan",
		"kw": "Kuwait",
		"la": "Laos",
		"lv": "Latvia",
		"lb": "Lebanon",
		"lr": "Liberia",
		"lt": "Lithuania",
		"lu": "Luxembourg",
		"mo": "Macau",
		"mk": "Macedonia",
		"mg": "Madagascar",
		"mw": "Malawi",
		"my": "Malaysia",
		"ml": "Mali",
		"mt": "Malta",
		"mr": "Mauritania",
		"mu": "Mauritius",
		"mx": "Mexico",
		"md": "Moldova",
		"mn": "Mongolia",
		"ms": "Montserrat",
		"mz": "Mozambique",
		"na": "Namibia",
		"np": "Nepal",
		"nl": "Netherlands",
		"nz": "New Zealand",
		"ni": "Nicaragua",
		"ne": "Niger",
		"ng": "Nigeria",
		"no": "Norway",
		"om": "Oman",
		"pk": "Pakistan",
		"pw": "Palau",
		"pa": "Panama",
		"pg": "Papua New Guinea",
		"py": "Paraguay",
		"pe": "Peru",
		"ph": "Philippines",
		"pl": "Poland",
		"pt": "Portugal",
		"qa": "Qatar",
		"tt": "Republic of Trinidad and Tobago",
		"ro": "Romania",
		"ru": "Russia",
		"kn": "Saint Kitts and Nevis",
		"lc": "Saint Lucia",
		"vc": "Saint Vincent and the Grenadines",
		"st": "Sao Tome e Principe",
		"sa": "Saudi Arabia",
		"sn": "Senegal",
		"sc": "Seychelles",
		"sl": "Sierra Leone",
		"sg": "Singapore",
		"sk": "Slovakia",
		"si": "Slovenia",
		"sb": "Soloman Islands",
		"za": "South Africa",
		"kr": "South Korea",
		"es": "Spain",
		"lk": "Sri Lanka",
		"sr": "Suriname",
		"sz": "Swaziland",
		"se": "Sweden",
		"ch": "Switzerland",
		"tw": "Taiwan",
		"tj": "Tajikistan",
		"tz": "Tanzania",
		"th": "Thailand",
		"tn": "Tunisia",
		"tr": "Turkey",
		"tm": "Turkmenistan",
		"tc": "Turks and Caicos Islands",
		"ug": "Uganda",
		"ua": "Ukraine",
		"ae": "United Arab Emirates",
		"us": "United States of America",
		"uy": "Uruguay",
		"uz": "Uzbekistan",
		"ve": "Venezuela",
		"vn": "Vietnam",
		"ye": "Yemen",
		"zw": "Zimbabwe",
	}

	validAnalysisChecks = map[AnalysisCheck]bool {
		DoPList: true,
		DoFiles: true,
		DoCode: true,
		DoBinary: true,
		DoStore: true,
	}
)

func countryCodesValidator(fl validator.FieldLevel) bool {
	repr := fl.Field().String()
	return len(ItunesCountryCodes[repr]) > 0
}

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
