package ios

import (
	"fmt"
	"github.com/simplycubed/vulnscan/malware"
	"github.com/simplycubed/vulnscan/printer"
	"github.com/simplycubed/vulnscan/utils"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)


//
func ListFiles(src string) (map[string]interface{}, error) {
	var fileList = map[string]interface{}{
		"files": []string{},
		"certs": []string{},
		"database": []string{},
		"plist": []string{},
	}
	walkErr := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		filePath := path
		dirName, fileName := filepath.Split(path)
		if !strings.HasSuffix(fileName, ".DS_Store") {
			if strings.Contains(fileName, "+") {
				plus2X := filepath.Join(dirName, strings.Replace(fileName, "+", "x", -1))
				err := os.Rename(filePath, plus2X)
				if err != nil {
					return err
				}
				filePath = plus2X
			}
			fileParam := strings.Replace(filePath, src, "", 1)
			fileList["files"] = append(fileList["files"].([]string), fileParam)
			ext := filepath.Ext(fileName)
			if r, _ := regexp.MatchString(`cer|pem|cert|crt|pub|key|pfx|p12`, ext); r {
				fileList["certs"] = append(fileList["certs"].([]string), fileParam)
			}
			if r, _ := regexp.MatchString(`db|sqlitedb|sqlite`, ext); r {
				fileList["database"] = append(fileList["database"].([]string), fileParam)
			}
			if r, _ := regexp.MatchString(`plist`, ext); r {
				fileList["plist"] = append(fileList["plist"].([]string), fileParam)
			}
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return fileList, nil
}

func StaticAnalyzer(src string, isSrc bool, country string, virus bool, print printer.Printer) error {
	type analysisResult struct {
		result map[string]interface{}
		format printer.FormatMethod
	}
	type analysisError map[string]interface{}

	nStreams := 5
	if !isSrc && virus {
		nStreams += 1
	}
	fmt.Printf("N streams %d\n", nStreams)
	if err := utils.Normalize(src, isSrc, func(p string) error {
		// Here src is the raw file, p is the normalized, unzipped directory
		resultStream := make(chan analysisResult, nStreams)
		errorStream := make(chan analysisError)
		// PList and app store search
		go func() {
			r, e := PListAnalysis(p, isSrc)
			if e != nil {
				errorStream <- analysisError{"error": e, "analysis": "plist"}
				errorStream <- analysisError{"error": fmt.Errorf("cannot make store analysis without plist analysis"), "analysis": "store"}
				return
			}
			resultStream <- analysisResult{r, printer.PList}
			resultStream <- analysisResult{Search(r["id"].(string), country), printer.Store }
		}()
		// File search
		go func() {
			r, e := ListFiles(p)
			if e != nil {
				errorStream <- analysisError{"error": e, "analysis": "files"}
				return
			}
			resultStream <- analysisResult{r, printer.ListFiles}
		}()
		// Virus Analysis
		if !isSrc && virus {
			go func() {
				client, e := malware.NewVirusTotalClient(os.Getenv("VIRUS_TOTAL_API_KEY"))
				if e != nil {
					errorStream <- analysisError{"error": e, "analysis": "virus"}
					return
				}
				hash, e := utils.HashMD5(src)
				if e != nil {
					errorStream <- analysisError{"error": e, "analysis": "virus"}
					return
				}
				r, e := client.GetResult(src, hash)
				if e != nil {
					errorStream <- analysisError{"error": e, "analysis": "virus"}
					return
				}
				resultStream <- analysisResult{r, printer.VirusScan}
			}()
		}
		// Code analysis
		go func() {
			r, e := CodeAnalysis(p)
			if e != nil {
				errorStream <- analysisError{"error": e, "analysis": "code"}
				return
			}
			resultStream <- analysisResult{r, printer.Code}
		}()
		// Binary analysis
		go func() {
			if isSrc {
				errorStream <- analysisError{"error": fmt.Errorf("skipping binary analysis on source data"), "analysis": "binary"}
				return
			}
			r, e := BinaryAnalysis(p, isSrc, "")
			if e != nil {
				errorStream <- analysisError{ "error": e, "analysis": "binary" }
				return
			}
			resultStream <- analysisResult{r, printer.Binary }
		}()
		for i := 0; i < nStreams; i++ {
			select {
			case e := <-errorStream:
				print.Log(e, nil, printer.Error)
			case res := <- resultStream:
				print.Log(res.result, nil, res.format)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if err := print.Generate(os.Stdout); err != nil {
		return err
	}
	return nil
}