package logrus

import (
	"fmt"
	"github.com/joseincandenza/vulnscan/printer"
	"strings"
)

type Formatter func(printer.AnalysisResult, error, printer.FormatMethod) map[string]map[string]interface{}

func DefaultFormat(res printer.AnalysisResult, e error, m printer.FormatMethod) map[string]map[string]interface{} {
	var output = map[string]map[string]interface{}{}
	var errorMessage = func(a string, e error) map[string]map[string]interface{} {
		output["Error"] =  map[string]interface{}{ "analysis": a, "message": e.Error()  }
		return output
	}
	switch m {
	case printer.Store:
		if e != nil {
			return errorMessage("store", e)
		}
		output["Total results"] = map[string]interface{}{ "analysis": "store",  "count": res["count"] }
		for i, r := range res["results"].([]map[string]interface{}) {
			output[fmt.Sprintf("Result %d", i + 1)] = map[string]interface{}{
				"analysis": "store", "title": r["title"], "url": r["url"],
			}
		}
	case printer.PList:
		if e != nil {
			return errorMessage("store", e)
		}
		generalMap, bundleMap := map[string]interface{}{  "analysis": "plist"  }, map[string]interface{}{ "analysis": "plist" }
		for k, v := range res {
			if k == "permissions"{
				for i, m := range v.([]map[string]interface{}) {
					output[fmt.Sprintf("Permission %d", i + 1)] = map[string]interface{}{ "analysis": "plist" }
					for k, v := range m {
						output[fmt.Sprintf("Permission %d", i + 1)][k] =  v
					}
				}
			} else if k == "insecure_connections" {
				connMap := v.(map[string]interface{})
				output["Insecure connections"] = map[string]interface{}{
					"analysis": "plist",
					"allow_arbitrary_loads": connMap["allow_arbitrary_loads"],
					"domains": strings.Join(connMap["domains"].([]string), ", "),
				}
			} else if strings.HasPrefix(k, "bundle") {
				bundleMap[k] = v
			} else {
				generalMap[k] = v
			}
		}
		output["General information"] =  generalMap
		output["Bundle information"] = bundleMap
	}
	return output
}
