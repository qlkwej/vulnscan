package store

import (
	"encoding/json"
	"fmt"
	"github.com/simplycubed/vulnscan/adapters"
	"github.com/simplycubed/vulnscan/adapters/output"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
	"net/http"
)

func Analysis(command utils.Command, entity *entities.StoreAnalysis, adapter adapters.AdapterMap) {
	output.CheckNil(adapter)
	var analysisName = entities.Files
	_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "starting"))
	lookupURL := "https://itunes.apple.com/lookup"
	reqURL := fmt.Sprintf("%s?bundleId=%s&country=%s&entity=software", lookupURL, command.AppId, command.Country)
	client := &http.Client{}
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		_ = adapter.Output.Error(output.ParseError(command, analysisName, fmt.Errorf("error creating store request: %s", err)))
		return
	}
	req.Header.Add("User-Agent",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36")
	_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, fmt.Sprintf("calling %s", reqURL)))
	res, err := client.Do(req)
	if err != nil {
		_ = adapter.Output.Error(output.ParseError(command, analysisName, fmt.Errorf("error contacting to the app store: %s", err)))
		return
	}
	_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "response from app store obtained"))
	err = json.NewDecoder(res.Body).Decode(&entity)
	if err != nil {
		_ = adapter.Output.Error(output.ParseError(command, analysisName, fmt.Errorf("error decoding store result: %s", err)))
		return
	}
	_ = res.Body.Close()
	_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "finished"))
	if err := adapter.Output.Result(command, entity); err != nil {
		_ = adapter.Output.Error(output.ParseError(command, analysisName, err))
	}
}
