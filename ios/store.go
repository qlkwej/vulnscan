package ios

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)


// Search gets iOS app details from App Store. The returned json from the service follows the schema:
// 		{
// 			"resultCount":1,
// 			"results": [{
// 				"advisories":							[]string,
// 				"appletvScreenshotUrls":				[]string,
// 				"artistId":								float,
// 				"artistName":							string,
// 				"artistViewUrl":						string,
// 				"artworkUrl100": 						string,
// 				"artworkUrl512":						string,
// 				"artworkUrl60":							string,
// 				"averageUserRating":					float,
// 				"averageUserRatingForCurrentVersion":	float,
// 				"bundleId":								string,
// 				"contentAdvisoryRating":				string,
// 				"currency":								string,
// 				"currentVersionReleaseDate": 			string,
// 				"description":							string,
// 				"features":								[]string,
// 				"fileSizeBytes":						string,
// 				"formattedPrice":						string,
// 				"genreIds":								[]string,
// 				"genres":								[]string,
// 				"ipadScreenshotUrls":					[]string,
// 				"isGameCenterEnabled":					bool,
// 				"isVppDeviceBasedLicensingEnabled":		bool,
// 				"kind":									string,
// 				"languageCodesISO2A":					[]string,
// 				"minimumOsVersion":						string,
// 				"price":								float,
// 				"primaryGenreId":						int,
// 				"primaryGenreName":						string,
// 				"releaseDate":							string,
// 				"releaseNotes":							string,
// 				"screenshotUrls":						[]string,
// 				"sellerName":							string,
// 				"sellerUrl":							string,
// 				"supportedDevices":						[]string,
// 				"trackCensoredName":					string,
// 				"trackContentRating":					string,
// 				"trackId":								float,
// 				"trackName":							string,
// 				"trackViewUrl":							string,
// 				"userRatingCount":						int,
// 				"userRatingCountForCurrentVersion":		int,
// 				"version":								string,
// 				"wrapperType":							string
// 			}]
//		}
// It is transformed into this map by the method:
// 		{
//			"count":	int,
///			"results":  [{
// 				features         	[]string 	`json:"features"`
//				icon_url_512       	string   	`json:"artworkUrl512"`
//				icon_url_100       	string   	`json:"artworkUrl100"`
//				icon_url_60        	string   	`json:"artworkUrl60"`
//				developer_id      	int      	`json:"artistId"`
//				developer_name    	string   	`json:"artistName"`
//				developer_url     	string   	`json:"artistViewUrl"`
//				developer_website 	string   	`json:"sellerUrl"`
//				supported_devices 	[]string 	`json:"supportedDevices"`
//				title            	string   	`json:"trackName"`
//				app_id            	string   	`json:"bundleId"`
//				categories       	[]string 	`json:"genres"`
//				description      	string   	`json:"description"`
//				price            	float32  	`json:"price"`
//				url        			string   	`json:"trackViewUrl"`
//				score            	float32  	`json:"averageUserRating"`
// 			}]
func Search(appID string, country string) map[string]interface{} {
	log.Printf("Fetching Details from App Store: %s", appID)
	lookupURL := "https://itunes.apple.com/lookup"
	reqURL := fmt.Sprintf("%s?bundleId=%s&country=%s&entity=software", lookupURL, appID, country)

	fmt.Println(reqURL)

	searchResult := map[string]interface{}{}
	output := map[string]interface{}{}
	client := &http.Client{}
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("User-Agent",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36")
	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&searchResult)

	if err != nil {
		log.Fatal(err)
	}

	output["count"] = int(searchResult["resultCount"].(float64))
	output["results"] = []map[string]interface{}{}
	for _, r := range searchResult["results"].([]interface{}) {
		result := map[string]interface{}{}
		for k, v := range map[string]string{
			"features":          "features",
			"artworkUrl512":     "icon_url_512",
			"artworkUrl100":     "icon_url_100",
			"artworkUrl60":      "icon_url_60",
			"artistId":          "developer_id",
			"artistName":        "developer_name",
			"artistViewUrl":     "developer_url",
			"sellerUrl":         "developer_website",
			"supportedDevices":  "supported_devices",
			"trackName": 		 "title",
			"bundleId":			 "app_id",
			"genres":            "categories",
			"price":             "price",
			"trackViewUrl":      "url",
			"averageUserRating": "score",
		}{
			result[v] = r.(map[string]interface{})[k]
		}
		output["results"] = append(output["results"].([]map[string]interface{}), result)
	}
	return output
}
