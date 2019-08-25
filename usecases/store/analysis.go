package store

import (
	"encoding/json"
	"fmt"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
	"net/http"
)

func Analysis(command utils.Command, entity *entities.StoreAnalysis) (entities.Entity, error) {
	lookupURL := "https://itunes.apple.com/lookup"
	reqURL := fmt.Sprintf("%s?bundleId=%s&country=%s&entity=software", lookupURL, command.AppId, command.Country)
	client := &http.Client{}
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return entity, fmt.Errorf("error creating store request: %s", err)
	}
	req.Header.Add("User-Agent",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36")
	res, err := client.Do(req)
	if err != nil {
		return entity, fmt.Errorf("error contacting to the app store: %s", err)
	}
	err = json.NewDecoder(res.Body).Decode(&entity)
	if err != nil {
		return entity, fmt.Errorf("error decoding store result: %s", err)
	}
	err = res.Body.Close()
	return entity, err
}
