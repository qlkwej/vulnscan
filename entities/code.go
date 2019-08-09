package entities

type (
	Level string
	Match func(string) bool

	CodeRule struct {
		// Description of the code rule
		Desc  	string 		`json:"desc" validate:"min=1"`
		// level of the issue
		Level 	Level		`json:"level" validate:"required,valid_levels"`
		Cvss  	float32 	`json:"cvss"  validate:"required"`
		Cwe   	string 		`json:"cwe"   validate:"startswith=CWE-"`
	}

	CodeMatcher struct {
		CodeRule
		// func (string) bool to call against a string to do the match
		Match 	Match 		`json:"match" validate:"required"`
	}

	CodeFinding struct {
		CodeRule
		Paths 	[]string 	`json:"paths" validate:"min=1"`
	}

	ApiRule struct {
		Description string `json:"description" validate:"min=1"`
	}

	ApiMatcher struct {
		ApiRule
		Match 	Match 		`json:"match" validate:"required"`
	}

	ApiFinding struct {
		ApiRule
		Paths 	[]string 	`json:"paths" validate:"min=1"`
	}

	UrlFinding struct {
		Url		string 		`json:"url" validate:"min=1"`
		Paths 	[]string	`json:"paths" validate:"min=1"`
	}

	EmailFinding struct {
		Email 	string		`json:"email" validate:"min=1"`
		Paths  	[]string	`json:"paths" validate:"min=1"`
	}

	CodeAnalysis struct {
		Codes 		[]CodeFinding 	`json:"codes" validate:"required"`
		Apis 		[]ApiFinding	`json:"apis" validate:"required"`
		Urls 		[]UrlFinding  	`json:"urls" validate:"required"`
		Emails 		[]EmailFinding	`json:"emails" validate:"required"`
		BadDomains 	[]string		`json:"bad_domains" validate:"required"`
	}
)
