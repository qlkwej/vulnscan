package logrus

import (
	"fmt"
	"strings"

	"github.com/simplycubed/vulnscan/printer"
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
			return errorMessage("plist", e)
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
	case printer.ListFiles:
		if e != nil {
			return errorMessage("files", e)
		}
		output["Total files"] = map[string]interface{}{ "analysis": "files",  "count": len(res["files"].([]string)) }
		for k, v := range map[string]string{"Plist files": "plist", "Databases": "database", "Certificates": "certs"} {
			if count := len(res[v].([]string)); count > 0 {
				output[fmt.Sprintf("%s found", k)] = map[string]interface{}{
					"analysis": "files",  "count": count, "files": fmt.Sprintf("%v", res[v]) }
			} else {
				output[fmt.Sprintf("%s not found", k)] = map[string]interface{}{"analysis": "files" }
			}
		}
		if len(output) == 0{
			output["Nothing found"] = map[string]interface{}{"analysis": "files"}
		}
	case printer.VirusScan:
		if e != nil {
			return errorMessage("virus", e)
		}
		if msg := res["verbose_msg"]; msg == "Scan request successfully queued, come back later for the report" {
			output["Virus scan queued, retrieve the result repeating the analysis or visiting the file link"] =
				map[string]interface{}{"analysis": "virus", "link": res["permalink"]}
		} else if msg == "Scan finished, information embedded" {
			output["Virus scan completed"] = map[string]interface{}{ "analysis": "virus",
				"performed": res["total"], "positive": res["positives"] }
			for aN, a := range res["scans"].(map[string]interface{}) {
				if aM := a.(map[string]interface{}); aM["detected"].(bool) {
					output[fmt.Sprintf("Scan %s", aN)] = map[string]interface{}{ "analysis": "virus",
						"positive": "yes", "result": aM["result"]}
				} else {
					output[fmt.Sprintf("Scan %s", aN)] = map[string]interface{}{ "analysis": "virus",
						"positive": "no"}
				}
			}
		}
	case printer.Code:
		if e != nil {
			return errorMessage("code", e)
		}
		messages := map[string]string {
			"code": "code issues",
			"api": "api uses",
			"url": "url inserted in the code",
			"email": "emails inserted in the code",
			"bad_domains": "dangerous domains references in the code",
		}
		for k, v := range res {
			if k == "code" || k == "api" {
				if l := len(v.(map[string]map[string]interface{})); l != 0 {
					output[fmt.Sprintf("Found %s", messages[k])] = map[string]interface{}{
						"analysis": "code", "found": l, "list": v}
				}
			} else if k == "url" || k == "email" {
				if l := len(v.(map[string][]string)); l != 0 {
					output[fmt.Sprintf("Found %s", messages[k])] = map[string]interface{}{
						"analysis": "code", "found": l, "list": v}
				}
			} else if k == "bad_domains" {
				if l := len(v.([]string)); l != 0 {
					output[fmt.Sprintf("Found %s", messages[k])] = map[string]interface{}{
						"analysis": "code", "found": l, "list": v}
				}
			}
		}
		if len(output) == 0{
			output["Nothing found"] = map[string]interface{}{"analysis": "code"}
		}
	}
	return output
}
