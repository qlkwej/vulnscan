package logrus

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/joho/godotenv"
	"github.com/simplycubed/vulnscan/malware"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/simplycubed/vulnscan/ios"
	"github.com/simplycubed/vulnscan/printer"
	"github.com/simplycubed/vulnscan/utils"
)

func TestNewPrinter(t *testing.T) {
	jsonStdOutPrinter := NewPrinter(Json, StdOut, DefaultFormat)
	jsonTextPrinter := NewPrinter(Json, Text, DefaultFormat)
	logStdOutPrinter := NewPrinter(Log, StdOut, DefaultFormat)
	logTextPrinter := NewPrinter(Log, Text, DefaultFormat)
	for i, printers := range [][]*Printer{
		{
			{
				logrus.Logger{
					Out:       os.Stdout,
					Formatter: new(logrus.JSONFormatter),
					Hooks:     make(logrus.LevelHooks),
					Level:     logrus.DebugLevel,
				},
				DefaultFormat,
				Json,
				StdOut,
			},
			jsonStdOutPrinter,
		},
		{
			{logrus.Logger{
				Out:       new(TextWriter),
				Formatter: new(logrus.JSONFormatter),
				Hooks:     make(logrus.LevelHooks),
				Level:     logrus.DebugLevel,
			},
				DefaultFormat,
				Json,
				Text,
			},
			jsonTextPrinter,
		},
		{
			{logrus.Logger{
				Out:       os.Stdout,
				Formatter: new(logrus.TextFormatter),
				Hooks:     make(logrus.LevelHooks),
				Level:     logrus.DebugLevel,
			},
				DefaultFormat,
				Log,
				StdOut,
			},
			logStdOutPrinter,
		},
		{
			{logrus.Logger{
				Out:       new(TextWriter),
				Formatter: new(logrus.JSONFormatter),
				Hooks:     make(logrus.LevelHooks),
				Level:     logrus.DebugLevel,
			},
				DefaultFormat,
				Log,
				Text,
			},
			logTextPrinter,
		},
	} {
		if printers[0].output != printers[1].output || printers[0].kind != printers[1].kind {
			t.Errorf("Generation of printer %d failed, expected %+v, got %+v", i, printers[0], printers[1])
		}
	}
}

func TestPrintItunesJson(t *testing.T) {
	jsonTextPrinter := NewPrinter(Json, Text, DefaultFormat)
	res := ios.Search("com.easilydo.mail", "us")
	jsonTextPrinter.Log(res, nil, printer.Store)
	var jsonResults [2]map[string]interface{}
	for i, s := range jsonTextPrinter.log.Out.(*TextWriter).inner {
		_ = json.Unmarshal([]byte(s), &jsonResults[i])
	}
	for i, test := range [][3]interface{}{
		{0, "count", float64(1)},
		{0, "msg", "Total results"},
		{1, "msg", "Result 1"},
		{1, "title", "Email - Edison Mail"},
		{1, "url", "https://apps.apple.com/us/app/email-edison-mail/id922793622?uo=4"},
	} {
		if out, expected := jsonResults[test[0].(int)][test[1].(string)], test[2]; out != expected {
			t.Errorf("error in itunes result json %d: got %#v, expected %#v", i, out, expected)
		}
	}
}

func TestPrintItunesLog(t *testing.T) {
	logTextPrinter := NewPrinter(Log, Text, DefaultFormat)
	res := ios.Search("com.easilydo.mail", "us")
	logTextPrinter.Log(res, nil, printer.Store)
	results := logTextPrinter.log.Out.(*TextWriter).inner
	// Fix test failing sometimes
	if !strings.Contains(results[0], "Total") {
		mainString := results[1]
		results[1] = results[0]
		results[0] = mainString
	}
	for _, test := range [][3]interface{}{
		{0, "count", "=1"},
		{0, "msg", "=\"Total results\""},
		{1, "msg", "=\"Result 1\""},
		{1, "title", "=\"Email - Edison Mail\""},
		{1, "url", "=\"https://apps.apple.com/us/app/email-edison-mail/id922793622?uo=4\""},
	} {
		keyPosition := strings.Index(results[test[0].(int)], test[1].(string))
		if expected, got := keyPosition+len(test[1].(string)),
			strings.Index(results[test[0].(int)], test[2].(string)); expected != got {
			t.Errorf("error in itunes result log for result %d, key %s, expected position %d, got %d. "+
				"Complete output: %s", test[0].(int), test[1].(string), expected, got, results[test[0].(int)])
		}
	}
}

func TestPrintPListJson(t *testing.T) {
	zipFile, e := utils.FindTest("apps", "source.zip")
	path, e := utils.FindTest("apps", "source")
	if e != nil { t.Error(e) }
	if err := utils.WithUnzip(zipFile, path, func(p string) error {
		jsonTextPrinter := NewPrinter(Json, Text, DefaultFormat)
		res, err := ios.PListAnalysis(p, true)
		if err != nil {
			return err
		}
		jsonTextPrinter.Log(res, err, printer.PList)
		var jsonResults [3]map[string]interface{}
		for i, s := range jsonTextPrinter.log.Out.(*TextWriter).inner {
			jsonResults[i] = map[string]interface{}{}
			_ = json.Unmarshal([]byte(s), &jsonResults[i])
		}
		for _, test := range [][3]interface{}{
			{0, "allow_arbitrary_loads", false},
			{0, "msg", "Insecure connections"},
			{1, "build", "1"},
			{1, "msg", "General information"},
			{2, "msg", "Bundle information"},
		} {
			if out, expected := jsonResults[test[0].(int)][test[1].(string)], test[2]; out != expected {
				t.Errorf("error in itunes result json: got %#v, expected %#v", out, expected)
				t.Errorf("Results: %#v", jsonResults)
			}
		}
		return nil
	}); err != nil {
		t.Errorf("Unzip error %s", err)
	}
}

func TestPrintPListLog(t *testing.T) {
	zipFile, e := utils.FindTest("apps", "source.zip")
	path, e := utils.FindTest("apps", "source")
	if e != nil { t.Error(e) }
	if err := utils.WithUnzip(zipFile, path, func(p string) error {
		logTextPrinter := NewPrinter(Log, Text, DefaultFormat)
		res, err := ios.PListAnalysis(p, true)
		logTextPrinter.Log(res, err, printer.PList)
		results := logTextPrinter.log.Out.(*TextWriter).inner
		// Fix tests failing sometimes
		r0, r1, r2 := "", "", ""
		for _, r := range results {
			if strings.Contains(r, "Insecure connections") {
				r0 = r
			} else if strings.Contains(r, "General information") {
				r1 = r
			} else if strings.Contains(r, "Bundle information") {
				r2 = r
			}
		}
		results[0], results[1], results[2] = r0, r1, r2
		for _, test := range [][3]interface{}{
			{0, "allow_arbitrary_loads", "=false"},
			{0, "msg", "=\"Insecure connections"},
			{1, "build", "=1"},
			{1, "msg", "=\"General information"},
			{2, "msg", "=\"Bundle information"},
		} {
			keyPosition := strings.Index(results[test[0].(int)], test[1].(string))
			if expected, got := keyPosition+len(test[1].(string)),
				strings.Index(results[test[0].(int)], test[2].(string)); expected != got {
				t.Errorf("error in itunes result log for result %d, key %s, expected position %d, got %d. "+
					"Complete output: %s", test[0].(int), test[1].(string), expected, got, results[test[0].(int)])
			}
		}
		return nil
	}); err != nil {
		t.Errorf("Unzip error %s", err)
	}
}

func TestPrintFilesLog(t *testing.T) {
	ipaFile, _ := utils.FindTest("apps", "binary.ipa")
	if e := utils.Normalize(ipaFile, false, func(p string) error {
		if res, err := ios.ListFiles(p); err != nil {
			t.Errorf("List files analysis failed with error %s", err)
		} else {
			logTextPrinter := NewPrinter(Log, Text, DefaultFormat)
			logTextPrinter.Log(res, err, printer.ListFiles)
			results := logTextPrinter.log.Out.(*TextWriter).inner
			for _, r := range results {
				if strings.Contains(r, "Total files") {
					if countIndex := strings.Index(r, "count") +
						len("count") + 1; countIndex < 0 || r[countIndex:countIndex+4] != "1896" {
						t.Errorf("Unexpected number of files, expected 1896, found %s", r[countIndex:countIndex+4])
					}
				} else if strings.Contains(r, "Databases") {
					if strings.Contains(r, "count") {
						t.Errorf("Unexpected tag count in Databases message")
					}
				} else if strings.Contains(r, "Plist") {
					if !strings.Contains(r, "count") {
						t.Errorf("Count tag not found in Plist message")
					}
				}
			}
		}
		return nil
	}); e != nil {
		t.Errorf("%v", e)
	}
}


func TestPrintVirus(t *testing.T) {
	ipaFile, _ := utils.FindTest("apps", "binary.ipa")
	mainfFolder, _ := utils.FindMainFolder()
	err := godotenv.Load(mainfFolder + string(os.PathSeparator) + ".env")
	if err != nil {
		t.Error("Error loading .env file")
	}
	apiKey := os.Getenv("VIRUS_TOTAL_API_KEY")
	if len(apiKey) == 0 {
		t.Error("Error loading VIRUS_TOTAL_API_KEY from .env file")
	}
	client, err := malware.NewVirusTotalClient(apiKey)
	if err != nil {
		t.Error(err)
	}
	hash, _ := utils.HashMD5(ipaFile)
	r, e := client.GetResult(ipaFile, hash)
	jsonTextPrinter := NewPrinter(Json, Text, DefaultFormat)
	jsonTextPrinter.Log(r, e, printer.VirusScan)
	var jsonResults []map[string]interface{}
	for i, s := range jsonTextPrinter.log.Out.(*TextWriter).inner {
		jsonResults = append(jsonResults, map[string]interface{}{})
		_ = json.Unmarshal([]byte(s), &jsonResults[i])
	}
	for _, j := range jsonResults {
		if j["msg"] == "Virus scan completed" {
			if j["performed"].(float64) < float64(40) || j["positive"] != float64(0) {
				t.Errorf("Wrong general message: %#v", j)
			}
		} else {
			if j["positive"] != "no" {
				t.Errorf("Wrong message for virus analysis %s: %#v", j["msg"].(string)[5:], j)
			}
		}
	}
}


func TestPrintCodeAnalysis(t *testing.T) {
	zip, _ := utils.FindTest("apps", "vulnerable_app.zip")
	src, _ := utils.FindTest("apps", "vulnerable_app")
	if err := utils.WithUnzip(zip, src, func(p string) error {
		result, e := ios.CodeAnalysis(p)
		if e != nil {
			t.Error(e)
		} else {
			jsonTextPrinter := NewPrinter(Json, Text, DefaultFormat)
			jsonTextPrinter.Log(result, e, printer.Code)
			var jsonResults [5]map[string]interface{}
			for i, s := range jsonTextPrinter.log.Out.(*TextWriter).inner {
				jsonResults[i] = map[string]interface{}{}
				_ = json.Unmarshal([]byte(s), &jsonResults[i])
			}
			printedAnalysis := map[string]bool {
				"Found api uses": false,
				"Found url inserted in the code": false,
				"Found emails inserted in the code": false,
				"Found code issues": false,
			}
			for _, j := range jsonResults {
				if _, ok := j["msg"]; ok {
					printedAnalysis[j["msg"].(string)] = true
				}
			}
			for an, p := range printedAnalysis {
				if !p {
					t.Errorf("%s not printed", an)
				}
			}
		}
		return nil
	}); err != nil {
		t.Errorf("%v", err)
	}
}


func TestPrintBinaryAnalysis(t *testing.T) {
	ipaPath, _ := utils.FindTest("apps", "binary.ipa")
	if analysis, err := ios.BinaryAnalysis(ipaPath, false, "iVim"); err != nil {
		t.Errorf("Error generating binary analysis: %s", err)
	} else {
		jsonTextPrinter := NewPrinter(Json, Text, DefaultFormat)
		jsonTextPrinter.Log(analysis, err, printer.Binary)
		var jsonResults []map[string]interface{}
		for i, s := range jsonTextPrinter.log.Out.(*TextWriter).inner {
			jsonResults = append(jsonResults, map[string]interface{}{})
			_ = json.Unmarshal([]byte(s), &jsonResults[i])
		}
		if len(jsonResults) != 16 {
			t.Errorf("Wrong number of logs, expected 16, found %d: %v", len(jsonResults), jsonResults)
		}

	}


}


func TestPrinterToString(t *testing.T) {
	zipFile, e := utils.FindTest("apps", "source.zip")
	path, e := utils.FindTest("apps", "source")
	if e != nil { t.Error(e) }
	if err := utils.WithUnzip(zipFile, path, func(p string) error {
		logTextPrinter := NewPrinter(Log, Text, DefaultFormat)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			res := ios.Search("com.easilydo.mail", "us")
			logTextPrinter.Log(res, nil, printer.Store)
		}()
		go func() {
			defer wg.Done()
			res, err := ios.PListAnalysis(p, true)
			logTextPrinter.Log(res, err, printer.PList)
		}()
		wg.Wait()
		buf := new(bytes.Buffer)
		e := logTextPrinter.Generate(buf)
		if e != nil {
			fmt.Printf("Error %s\n", e)
		}
		results := strings.Split(buf.String(), "\n")
		for i, test := range []string{"plist", "plist", "plist", "store", "store"} {
			if pos := strings.Index(results[i], "analysis") + len("analysis="); results[i][pos:pos+len(test)] != test {
				t.Errorf("Error in %d iteration, expected to find analysis %s, found %s", i, test, results[i][pos:pos+len(test)])
			}
		}
		return nil
	}); err != nil {
		t.Errorf("Unzip error %s", err)
	}
}
