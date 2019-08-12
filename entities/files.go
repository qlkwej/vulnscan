package entities

type (
	ListFiles struct {
		Files 			[]string `json:"files"`
		Certifications 	[]string `json:"certifications"`
		Database 		[]string `json:"database"`
		PLists 			[]string `json:"plists"`
	}

)
