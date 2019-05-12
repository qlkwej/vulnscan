package main

import (
	"log"
	"os"
	"path/filepath"
	"sort"

	"github.com/simplycubed/security-bench/ios"
	"gopkg.in/urfave/cli.v1"
)

func main() {

	var appID string
	var binaryPath string
	var country string
	var outputFormat string
	var sourcePath string

	app := cli.NewApp()
	app.Version = "0.0.1"
	app.Authors = []cli.Author{
		cli.Author{
			Name:  "Engineering",
			Email: "info@simplycubed.com",
		},
	}
	app.Copyright = "(c) 2019 SimplyCubed, LLC - Mozilla Public License 2.0"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "source, s",
			Value:       defaultPath(),
			Usage:       "Full path to source code directory",
			Destination: &sourcePath,
		},
		cli.StringFlag{
			Name:        "app, a",
			Value:       "",
			Usage:       "iTunes lookup application ID (i.e. com.easilydo.mail)",
			Destination: &appID,
		},
		cli.StringFlag{
			Name:        "country, c",
			Value:       "us",
			Usage:       "iTunes country/region",
			Destination: &country,
		},
		cli.StringFlag{
			Name:        "binary, b",
			Value:       "",
			Usage:       "Full path to binary (ipa) file",
			Destination: &binaryPath,
		},
		cli.StringFlag{
			Name:        "output format",
			Value:       "stdout",
			Usage:       "Output format (stdout, json)",
			Destination: &outputFormat,
		},
	}

	sort.Sort(cli.FlagsByName(app.Flags))
	sort.Sort(cli.CommandsByName(app.Commands))

	app.Action = func(c *cli.Context) error {

		ok, err := exists(sourcePath)
		if err != nil {
			log.Fatal(err)
		}

		if ok == true {
			log.Printf("Source Path: %s", sourcePath)
		}

		if appID != "" {
			printiTunesResults(appID, country)
		}

		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func defaultPath() string {
	dir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	return dir
}

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

func printiTunesResults(appID string, country string) {
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
