package logrus

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	}{
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
		{ 0, "count", float64(1) },
		{ 0, "msg", "Total results" },
		{ 1, "msg", "Result 1" },
		{ 1, "title", "Email - Edison Mail"},
		{ 1, "url",  "https://apps.apple.com/us/app/email-edison-mail/id922793622?uo=4"},
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
	for _, test := range [][3]interface{}{
		{ 0, "count", "=1" },
		{ 0, "msg", "=\"Total results\"" },
		{ 1, "msg", "=\"Result 1\"" },
		{ 1, "title", "=\"Email - Edison Mail\""},
		{ 1, "url",  "=\"https://apps.apple.com/us/app/email-edison-mail/id922793622?uo=4\""},
	} {
		keyPosition := strings.Index(results[test[0].(int)], test[1].(string))
		if expected, got := keyPosition + len(test[1].(string)),
		                    strings.Index(results[test[0].(int)], test[2].(string));
		expected != got {
			t.Errorf("error in itunes result log for result %d, key %s, expected position %d, got %d. " +
				"Complete output: %s", test[0].(int), test[1].(string), expected, got, results[test[0].(int)])
		}
	}
}

func TestPrintPListJson(t *testing.T) {
	zipFile, _ := filepath.Abs("../../test_files/plist/source.zip")
	path, _ := filepath.Abs("../../test_files/plist/source")
	if err:= utils.WithUnzip(zipFile, path, func() {
		jsonTextPrinter := NewPrinter(Json, Text, DefaultFormat)
		res, err := ios.PListAnalysis(path, true)
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
			}
		}
	}); err != nil {
		t.Errorf("Unzip error %s", err)
	}
}

func TestPrintPListLog(t *testing.T) {
	zipFile, _ := filepath.Abs("../../test_files/plist/source.zip")
	path, _ := filepath.Abs("../../test_files/plist/source")
	if err:= utils.WithUnzip(zipFile, path, func() {
		logTextPrinter := NewPrinter(Log, Text, DefaultFormat)
		res, err := ios.PListAnalysis(path, true)
		logTextPrinter.Log(res, err, printer.PList)
		results := logTextPrinter.log.Out.(*TextWriter).inner
		for _, test := range [][3]interface{}{
			{0, "allow_arbitrary_loads", "=false"},
			{0, "msg", "=\"Insecure connections"},
			{1, "build", "=1"},
			{1, "msg", "=\"General information"},
			{2, "msg", "=\"Bundle information"},
		} {
			keyPosition := strings.Index(results[test[0].(int)], test[1].(string))
			if expected, got := keyPosition + len(test[1].(string)),
				strings.Index(results[test[0].(int)], test[2].(string));
				expected != got {
				t.Errorf("error in itunes result log for result %d, key %s, expected position %d, got %d. " +
					"Complete output: %s", test[0].(int), test[1].(string), expected, got, results[test[0].(int)])
			}
		}
	}); err != nil {
		t.Errorf("Unzip error %s", err)
	}
}

func TestPrinterToString(t *testing.T) {
	zipFile, _ := filepath.Abs("../../test_files/plist/source.zip")
	path, _ := filepath.Abs("../../test_files/plist/source")
	if err:= utils.WithUnzip(zipFile, path, func() {
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
			res, err := ios.PListAnalysis(path, true)
			logTextPrinter.Log(res, err, printer.PList)
		}()
		wg.Wait()
		buf := new(bytes.Buffer)
		e := logTextPrinter.Generate(buf)
		if e != nil {
			fmt.Printf("Error %s\n", e)
		}
		results := strings.Split(buf.String(), "\n")
		for i, test := range []string{"plist", "plist", "plist", "store", "store" }{
			if pos := strings.Index(results[i], "analysis") + len("analysis="); results[i][pos:pos+len(test)] != test {
				t.Errorf("Error in %d iteration, expected to find analysis %s, found %s", i, test, results[i][pos:pos+len(test)] )
			}
		}
	}); err != nil {
		t.Errorf("Unzip error %s", err)
	}
}
