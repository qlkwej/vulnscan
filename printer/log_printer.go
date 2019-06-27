package printer

import (
	"github.com/simplycubed/vulnscan/ios"
	"log"
	"reflect"
)

type LogPrinter struct {}

func (p LogPrinter) PrintiTunesResults(appID string, country string) {
	resp := ios.Search(appID, country)
	if resp.ResultCount > 0 {
		log.Printf("Total Results: %d\n", resp.ResultCount)
		for _, r := range resp.Results {
			log.Printf("Title: %s\n", r.Title)
			log.Printf("URL: %s\n", r.ItunesURL)
		}
	} else {
		log.Printf("No results found: %s\n", appID)
	}
}

func (p LogPrinter) PrintPlistResults(src string, isSrc bool) {
	resp, err := ios.PListAnalysis(src, isSrc)
	if err != nil {
		log.Printf("Plist Analysis error: %s\n", err)
	}
	v := reflect.ValueOf(&resp).Elem()
	t := v.Type()

	var values = map[string]interface{}{}

	log.Printf("PList Analysis completed:\n")
	for i := 0; i < v.NumField(); i++ {
		log.Printf("%s: %v", values[t.Field(i).Name], v.Field(i).Interface())
	}
}
