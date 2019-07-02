package printer

import (
	"encoding/json"
	"github.com/joseincandenza/vulnscan/test_files"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestGet(t *testing.T) {
	jsonStdOutPrinter := Get(Json, StdOut)
	jsonTextPrinter := Get(Json, Text)
	logStdOutPrinter := Get(Log, StdOut)
	logTextPrinter := Get(Log, Text)
	for _, printers := range [][]*Printer{
		{
			{&logrus.Logger{
				Out:       os.Stdout,
				Formatter: new(logrus.JSONFormatter),
				Hooks:     make(logrus.LevelHooks),
				Level:     logrus.DebugLevel,
			},
				Json,
				StdOut,
			},
			&jsonStdOutPrinter,
		},
		{
			{&logrus.Logger{
				Out:       new(TextWriter),
				Formatter: new(logrus.JSONFormatter),
				Hooks:     make(logrus.LevelHooks),
				Level:     logrus.DebugLevel,
			},
				Json,
				Text,
			},
			&jsonTextPrinter,
		},
		{
			{&logrus.Logger{
				Out:       os.Stdout,
				Formatter: new(logrus.TextFormatter),
				Hooks:     make(logrus.LevelHooks),
				Level:     logrus.DebugLevel,
			},
				Log,
				StdOut,
			},
			&logStdOutPrinter,
		},
		{
			{&logrus.Logger{
				Out:       new(TextWriter),
				Formatter: new(logrus.JSONFormatter),
				Hooks:     make(logrus.LevelHooks),
				Level:     logrus.DebugLevel,
			},
				Json,
				Text,
			},
			&logTextPrinter,
		},
	}{
		if !reflect.DeepEqual(printers[0], printers[1]) {
			t.Errorf("Generation of printer failed, expected %+v, gor %+v", printers[0], printers[1])
		}
	}
}

func TestPrintItunesJson(t *testing.T) {
	jsonTextPrinter := Get(Json, Text)
	jsonTextPrinter.PrintiTunesResults("com.easilydo.mail", "us")
	var jsonResults [2]map[string]interface{}
	for i, s := range jsonTextPrinter.log.Out.(*TextWriter).inner {
		_ = json.Unmarshal([]byte(s), &jsonResults[i])
	}
	for _, test := range [][3]interface{}{
		{ 0, "count", float64(1) },
		{ 0, "msg", "Total results" },
		{ 1, "msg", "Result 1" },
		{ 1, "title", "Email - Edison Mail"},
		{ 1, "url",  "https://apps.apple.com/us/app/email-edison-mail/id922793622?uo=4"},
	} {
		if out, expected := jsonResults[test[0].(int)][test[1].(string)], test[2]; out != expected {
			t.Errorf("error in itunes result json: got %#v, expected %#v", out, expected)
		}
	}
}

func TestPrintItunesLog(t *testing.T) {
	logTextPrinter := Get(Log, Text)
	logTextPrinter.PrintiTunesResults("com.easilydo.mail", "us")
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
	zipFile, _ := filepath.Abs("../test_files/plist/source.zip")
	path, _ := filepath.Abs("../test_files/plist/source")
	if err:= test_files.WithUnzip(zipFile, path, func() {
		jsonTextPrinter := Get(Json, Text)
		jsonTextPrinter.PrintPlistResults(path, true)
		jsonResults := make([]map[string]interface{}, 10)
		for _, s := range jsonTextPrinter.log.Out.(*TextWriter).inner {
			jsonResult := map[string]interface{}{}
			_ = json.Unmarshal([]byte(s), &jsonResult)
			jsonResults = append(jsonResults, jsonResult)
		}
		t.Errorf("%s", jsonResults)
	}); err != nil {
		t.Errorf("Unzip error %s", err)
	}

}

func TestPrintPListLog(t *testing.T) {}
