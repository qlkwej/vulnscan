package ios

import (
	"github.com/simplycubed/vulnscan/malware"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func urlEmailExtract(data string) ([][]byte, [][]byte) {
	urlPat, _ := regexp.
		Compile(`((?:https?://|s?ftps?://|file://|javascript:|data:|www\d{0,3}[.])[\w().=/;,#:@?&~*+!$%\'{}-]+)`)
	emailPat, _ := regexp.Compile(`[\w.-]+@[\w-]+\.[\w.]+`)
	return urlPat.FindAll([]byte(data), -1), emailPat.FindAll([]byte(data), -1)
}


func CodeAnalysis(src string) (result map[string]interface{}, err error) {
	var codeFindings map[string]map[string]interface{}
	var apiFindings map[string]map[string]interface{}
	var urlFindings map[string][]string
	var emailFindings map[string][]string
	var urlList []string
	if walkErr := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if filepath.Ext(path) == ".m" {
			var jfilePath string
			if strings.Contains(filepath.Base(path), "+") {
				jfilePath := filepath.Join(filepath.Dir(path),
					strings.Replace(filepath.Base(path), "+", "x", -1))
				err := os.Rename(path, jfilePath)
				if err != nil {
					return err
				}
			} else {
				jfilePath = path
			}
			var data string
			if d, err := ioutil.ReadFile(jfilePath); err != nil {
				return err
			} else {
				data = string(d)
			}
			relativeSrcPath := strings.Replace(jfilePath, src, "", 1)
			for _, rule := range CodeRules {
				if rule.Match(data) {
					if r, ok := codeFindings[rule.Desc]; ok {
						codeFindings[rule.Desc]["path"] = append(r["path"].([]string), relativeSrcPath)
					} else {
						codeFindings[rule.Desc] = map[string]interface{}{
							"path": []string{relativeSrcPath},
							"level": rule.Level,
							"cvss": rule.Cvss,
							"cws": rule.Cwe,
						}
					}
				}
			}
			for _, api := range CodeAPIs {
				if api.Match(data) {
					if r, ok := apiFindings[api.Desc]; ok {
						apiFindings[api.Desc]["path"] = append(r["path"].([]string), relativeSrcPath)
					} else {
						apiFindings[api.Desc] = map[string]interface{}{
							"path": []string{relativeSrcPath},
						}
					}
				}
			}
			urls, emails := urlEmailExtract(data)
			for _, url := range urls {
				if r, ok := urlFindings[string(url)]; ok {
					urlFindings[string(url)] = append(r, relativeSrcPath)
					urlList = append(urlList, string(url))
				} else {
					urlFindings[string(url)] = []string{relativeSrcPath}
				}
			}
			for _, email := range emails {
				if r, ok := emailFindings[string(email)]; ok {
					emailFindings[string(email)] = append(r, relativeSrcPath)
				} else {
					emailFindings[string(email)] = []string{relativeSrcPath}
				}
			}
		}
		return nil
	}); walkErr != nil {
		return result, walkErr
	}
	return map[string]interface{}{
		"code": codeFindings,
		"api": apiFindings,
		"url": urlFindings,
		"email": emailFindings,
		"bad_domains": malware.MalwareCheck(urlList),
	}, nil

}
