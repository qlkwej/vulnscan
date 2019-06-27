package printer

import (
	"encoding/json"
	"github.com/simplycubed/vulnscan/ios"
	"log"
)

type JsonPrinter struct {}

func (p JsonPrinter) PrintiTunesResults(appID string, country string) {
	resp := ios.Search(appID, country)
	respJson, _ := json.Marshal(resp)
	log.Printf(string(respJson))
}


func (p JsonPrinter) PrintPlistResults(src string, isSrc bool) {
	resp, err := ios.PListAnalysis(src, isSrc)
	if err != nil {
		respJson, _ := json.Marshal(map[string]string{"error": err.Error()})
		log.Printf(string(respJson))
	}
	respJson, _ := json.Marshal(resp)
	log.Printf(string(respJson))
}