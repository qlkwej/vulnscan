package code

import (
	"fmt"
	"github.com/simplycubed/vulnscan/adapters"
	"github.com/simplycubed/vulnscan/adapters/output"
	"github.com/simplycubed/vulnscan/entities"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func Analysis(command entities.Command, entity *entities.CodeAnalysis, adapter adapters.AdapterMap) {
	output.CheckNil(adapter)
	var analysisName = entities.Code
	_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "starting"))
	if walkErr := filepath.Walk(command.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if filepath.Ext(path) == ".m" || filepath.Ext(path) == ".swift" {
			var jfilePath string
			// TODO: why are we doing this?
			if strings.Contains(filepath.Base(path), "+") {
				jfilePath = filepath.Join(filepath.Dir(path),
					strings.Replace(filepath.Base(path), "+", "x", -1))
				err := os.Rename(path, jfilePath)
				if err != nil {
					return fmt.Errorf("error moving file %s to %s: %s", path, jfilePath, err)
				}
			} else {
				jfilePath = path
			}

			var data string
			if d, err := ioutil.ReadFile(jfilePath); err != nil {
				return fmt.Errorf("error reading file %s: %s", jfilePath, err)
			} else {
				data = string(d)
			}
			relativeSrcPath := strings.Replace(jfilePath, command.Path, "", 1)
			ruleExtractor(data, relativeSrcPath, entity)
			apiExtractor(data, relativeSrcPath, entity)
			urlExtractor(data, relativeSrcPath, entity)
			emailExtractor(data, relativeSrcPath, entity)
		}
		return nil
	}); adapter.Output.Error(output.ParseError(command, analysisName, walkErr)) != nil {
		return
	}
	if a := adapter.Services.MalwareDomains; a != nil {
		if adapter.Output.Error(output.ParseError(command, analysisName, a(command, entity))) != nil {
			return
		}
	}
	_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "finished"))
	if err := adapter.Output.Result(command, entity); err != nil {
		_ = adapter.Output.Error(output.ParseError(command, analysisName, err))
	}
}

func ruleExtractor(data, path string, entity *entities.CodeAnalysis) {
	for _, rule := range Rules {
		if rule.Match(data) {
			var found bool
			for i, cf := range entity.Codes {
				if cf.Description == rule.Description {
					entity.Codes[i].Paths = append(entity.Codes[i].Paths, path)
					found = true
					break
				}
			}
			if !found {
				entity.Codes = append(entity.Codes, entities.CodeFinding{
					CodeRule: rule.CodeRule,
					Paths:    []string{path},
				})
			}
		}
	}
}

func apiExtractor(data, path string, entity *entities.CodeAnalysis) {
	for _, api := range APIs {
		if api.Match(data) {
			var found bool
			for i, af := range entity.Apis {
				if af.Description == api.Description {
					entity.Apis[i].Paths = append(entity.Apis[i].Paths, path)
					found = true
					break
				}
			}
			if !found {
				entity.Apis = append(entity.Apis, entities.ApiFinding{
					ApiRule: api.ApiRule,
					Paths:   []string{path},
				})
			}
		}
	}
}

func urlExtractor(data, path string, entity *entities.CodeAnalysis) {
	urlPat, _ := regexp.
		Compile(`https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+`)
	urls := urlPat.FindAll([]byte(data), -1)
	for _, url := range urls {
		var found bool
		for i, uf := range entity.Urls {
			if uf.Url == string(url) {
				entity.Urls[i].Paths = append(entity.Urls[i].Paths, path)
				found = true
				break
			}
		}
		if !found {
			entity.Urls = append(entity.Urls, entities.UrlFinding{
				Url:   string(url),
				Paths: []string{path},
			})
		}
	}
}

func emailExtractor(data, path string, entity *entities.CodeAnalysis) {
	emailPat, _ := regexp.Compile(`[\w.-]+@[\w-]+\.[\w.]+`)
	emails := emailPat.FindAll([]byte(data), -1)
	for email := range emails {
		var found bool
		for i, ef := range entity.Emails {
			if ef.Email == string(email) {
				entity.Emails[i].Paths = append(entity.Emails[i].Paths, path)
				found = true
				break
			}
		}
		if !found {
			entity.Emails = append(entity.Emails, entities.EmailFinding{
				Email: string(email),
				Paths: []string{path},
			})
		}
	}
}
