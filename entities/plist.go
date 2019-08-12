package entities

type (

	BundleUrlType struct {
		Name 	string  	`json:"name"`
		Schemas []string    `json:"schemas"`
	}

	UsageDescription struct {
		Name 		string `json:"name"`
		Description string `json:"description"`
		Reason 		string `json:"reason"`
	}

	InsecureConnections struct {
		AllowArbitraryLoads bool 	 `json:"allow_arbitrary_loads"`
		Domains 			[]string `json:"domains"`
	}

	PListAnalysis struct {
		Xml                      string   			`json:"xml"`
		BinName                  string   			`json:"bin_name"`
		Bin                      string   			`json:"bin"`
		Id                       string   			`json:"id"`
		Build                    string   			`json:"build"`
		SDK                      string   			`json:"sdk"`
		Platform                 string   			`json:"platform"`
		MinimumVersion           string   			`json:"minimum_version"`
		BundleName               string   			`json:"bundle_name"`
		BundleVersionName        string   			`json:"bundle_version_name"`
		BundleSupportedPlatforms []string 			`json:"bundle_supported_platforms"`
		BundleLocalizations      []string 			`json:"bundle_localizations"`
		BundleUrlTypes 			[]BundleUrlType		`json:"bundle_url_types"`
		Permissions 			[]UsageDescription  `json:"permissions"`
		InsecureConnections     InsecureConnections `json:"insecure_connections"`
	}
)

