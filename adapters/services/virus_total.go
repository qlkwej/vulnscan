package services

import (
	"encoding/json"
	"fmt"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const virusTotalBaseURL = "https://www.virustotal.com/vtapi/v2/"

type VirusTotalClient struct {
	apiKey string
	url    string
	c      *http.Client
}

func VirusTotalAdapter(command utils.Command, entity *entities.VirusAnalysis) (entities.Entity, error) {
	client, e := newVirusTotalClient(utils.Configuration.VirusScanKey)
	if e != nil {
		return entity, e
	}
	hash, e := utils.HashMD5(command.Path)
	if e != nil {
		return entity, e
	}
	r, e := client.GetResult(command.Path, hash)
	if e != nil {
		return entity, e
	}
	_ , e = entity.Response.FromMap(r)
	if e != nil {
		return entity, fmt.Errorf("error processing virus scan report map: %s", e)
	}
	_ , e = entity.Report.FromMap(r)
	if e != nil {
		return entity, fmt.Errorf("error processing virus scan report map: %s", e)
	}
	if entity.Report.ScanId != "" {
		entity.HasReport = true
	}
	return entity, nil
}

// Creates a new VirusTotalClient. If apiKey has len = 0, it searches for it as an environment variable, and fails,
// returning an error, if it can't find it.
func newVirusTotalClient(apiKey string) (*VirusTotalClient, error) {
	var key string
	if apiKey != "" {
		key = apiKey
	} else if k := os.Getenv("VIRUS_TOTAL_API_KEY"); k != "" {
		key = k
	} else {
		return nil, fmt.Errorf("api key for VirusTotal not found")
	}
	return &VirusTotalClient{
		key,
		virusTotalBaseURL,
		&http.Client{},
	}, nil
}

// Makes a call to virus scan api to scan file. First it tries to call to file/report endpoint with the md5 hash of
// the file to check if the analysis was already generated, if it wasn"t, it uploads the file to the file/scan endpoint.
// The returned report depends on the type of action that it"s triggered. If the report is not ready, and the function
// proceeds to upload the file, the response will have the following fields:
//		"response_code": 	int
//		"verbose_msg": 		string
//		"resource": 		string
// 		"scan_id": 			string
//      "sha256":			string
// 		"permalink": 		string
// If the scan is ready, and the method proceeds to download the result, the response will contain this additional
// fields:
// 		"md5": 				string
// 		"sha1": 			string
// 		"scan_date": 		string
// 		"positives": 		int
// 		"total": 			int
// 		"scans": 			map[string] {
// 			"detected":			bool
//			"version":			string
//			"result":			string
//			"update":			string
//			}
// 		}
func (client *VirusTotalClient) GetResult(path, hash string) (r map[string]interface{}, err error) {
	r, err = client.makeApiRequest("GET", "file/report", map[string]string{"resource": hash})
	if err != nil {
		return nil, err
	}
	if m, ok := r["verbose_msg"]; ok {
		if m != "The requested resource is not among the finished, queued or pending scans" {
			return r, nil
		}
	}
	r, err = client.makeApiRequest("POST", "file/scan", map[string]string{"file": path})
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (client *VirusTotalClient) makeApiRequest(
	method, apiURL string, parameters map[string]string) (result map[string]interface{}, err error) {
	fullUrl := client.url + apiURL
	parameters["apikey"] = client.apiKey
	var resp *http.Response
	if _, ok := parameters["file"]; ok && method == "POST" {
		resp, err = client.makeApiUploadRequest(fullUrl, parameters)
	} else {
		values := url.Values{}
		for k, v := range parameters {
			values.Add(k, v)
		}
		switch strings.ToUpper(method) {
		case "GET":
			req, err := http.NewRequest("GET", fullUrl+"?"+values.Encode(), nil)
			if err != nil {
				return result, err
			}
			resp, err = client.c.Do(req)
		case "POST":
			resp, err = client.c.PostForm(fullUrl, values)
		default:
			return result, fmt.Errorf("invalid method %s", method)
		}
	}
	if err != nil {
		return result, err
	}
	if err = handleError(resp); err != nil {
		return result, err
	}
	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	if err = dec.Decode(&result); err != nil {
		return result, err
	}
	return result, nil
}

func (client *VirusTotalClient) makeApiUploadRequest(
	fullUrl string, parameters map[string]string) (resp *http.Response, err error) {
	file, err := os.Open(parameters["file"])
	if err != nil {
		return nil, err
	}
	// create a multipat/mime writer
	bodyReader, bodyWriter := io.Pipe()
	writer := multipart.NewWriter(bodyWriter)
	contentType := writer.FormDataContentType()

	errChan := make(chan error, 1)
	go func() {
		defer bodyWriter.Close()
		//noinspection GoUnhandledErrorResult
		defer file.Close()
		part, err := writer.CreateFormFile("file", filepath.Base(parameters["file"]))
		fmt.Print(filepath.Base(parameters["file"]))
		if err != nil {
			errChan <- err
			return
		}
		if _, err := io.Copy(part, file); err != nil {
			errChan <- err
			return
		}
		delete(parameters, "file")
		fmt.Print(parameters)
		for k, v := range parameters {
			if err := writer.WriteField(k, v); err != nil {
				errChan <- err
				return
			}
		}
		errChan <- writer.Close()
	}()

	postReq, err := http.NewRequest("POST", fullUrl, bodyReader)
	if err != nil {
		return resp, err
	}
	postReq.Header.Add("Content-Type", contentType)

	resp, err = client.c.Do(postReq)
	if cerr := <-errChan; cerr != nil {
		return resp, cerr
	}
	return resp, nil
}

func handleError(resp *http.Response) error {
	if resp.StatusCode != http.StatusOK {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		return fmt.Errorf("unexpected status code: %d (%s)", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	return nil
}

