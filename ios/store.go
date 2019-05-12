package ios

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// App represents a single application in what can be many results
type App struct {
	Features         []string `json:"features"`
	IconURL512       string   `json:"artworkUrl512"`
	IconURL100       string   `json:"artworkUrl100"`
	IconURL60        string   `json:"artworkUrl60"`
	DeveloperID      int      `json:"artistId"`
	DeveloperName    string   `json:"artistName"`
	DeveloperURL     string   `json:"artistViewUrl"`
	DeveloperWebsite string   `json:"sellerUrl"`
	SupportedDevices []string `json:"supportedDevices"`
	Title            string   `json:"trackName"`
	AppID            string   `json:"bundleId"`
	Categories       []string `json:"genres"`
	Description      string   `json:"description"`
	Price            float32  `json:"price"`
	ItunesURL        string   `json:"trackViewUrl"`
	Score            float32  `json:"averageUserRating"`
	Error            bool
}

// SearchResult is the Apple Store lookup results for a specifc application
type SearchResult struct {
	ResultCount int   `json:"resultCount"`
	Results     []App `json:"results"`
}

// Search gets iOS app details from App Store
func Search(appID string, country string) SearchResult {
	log.Printf("Fetching Details from App Store: %s", appID)
	lookupURL := "https://itunes.apple.com/lookup"
	reqURL := fmt.Sprintf("%s?bundleId=%s&country=%s&entity=software", lookupURL, appID, country)

	fmt.Println(reqURL)

	client := &http.Client{}
	req, err := http.NewRequest("GET", reqURL, nil)
	req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36")
	res, err := client.Do(req)
	searchResult := SearchResult{}

	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&searchResult)
	if err != nil {
		log.Fatal(err)
	}
	return searchResult
}
