package main

import (
	"errors"
	"github.com/joseincandenza/vulnscan/printer"
	"log"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/urfave/cli.v1"
)

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


func checkPathIsSrc(binaryPath, sourcePath string) (string, bool) {
	sourceOK, sourceErr := exists(sourcePath)
	if sourceErr != nil {
		log.Fatal(sourceErr)
	}

	if sourceOK == true {
		log.Printf("Source Path: %s", sourcePath)
		return sourcePath, true
	}

	binaryOK, binaryErr := exists(binaryPath)
	if binaryErr != nil {
		log.Fatal(binaryErr)
	}

	if binaryOK == true {
		log.Printf("Binary Path: %s", binaryPath)
		return binaryPath, false
	}
	log.Fatal("Path doesn't exists")
	return "", false
}

func getApp() *cli.App {
	var appID string
	var binaryPath string
	var country string
	var sourcePath string
	var print string = "log"

	app := cli.NewApp()
	app.Version = "0.0.1"
	app.Name = "vulnscan"
	app.Usage = "iOS and MacOS vulnerability scanner"
	app.Authors = []cli.Author{
		{
			Name:  "Vulnscan Team",
			Email: "vulnscan@simplycubed.com",
		},
	}
	app.Copyright = "(c) 2019 SimplyCubed, LLC - Mozilla Public License 2.0"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "json, j",
			Value:       "",
			Destination: &print,
		},
	}
	app.Commands = []cli.Command{
		{
			Name:    "lookup",
			Aliases: []string{"l"},
			Usage:   "itunes app lookup",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:        "app, a",
					Value:       "",
					Usage:       "itunes app/bundle ID (i.e. com.easilydo.mail)",
					Destination: &appID,
				},
				cli.StringFlag{
					Name:        "country, c",
					Value:       "us",
					Usage:       "itunes country ID (i.e. us, jp)",
					Destination: &country,
				},
			},
			Action: func(c *cli.Context) error {
				if appID != "" {
					printer.Get(print).PrintiTunesResults(appID, country)
				} else {
					return errors.New("appID is required: `--app appID`")
				}
				return nil
			},
		},
		{
			Name: "plist",
			Aliases: []string{"p"},
			Usage:   "plists scan",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:        "binary, b",
					Value:       defaultPath(),
					Usage:       "Full path to binary (ipa) file",
					Destination: &binaryPath,
				},
				cli.StringFlag{
					Name:        "source, s",
					Value:       defaultPath(),
					Usage:       "Full path to source code directory",
					Destination: &sourcePath,
				},
			},
			Action: func(c *cli.Context) error {
				printer.Get(print).PrintPlistResults(checkPathIsSrc(binaryPath, sourcePath))
				return nil
			},
		},
		{
			Name:    "scan",
			Aliases: []string{"s"},
			Usage:   "source directory and binary file security scan",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:        "binary, b",
					Value:       defaultPath(),
					Usage:       "Full path to binary (ipa) file",
					Destination: &binaryPath,
				},
				cli.StringFlag{
					Name:        "source, s",
					Value:       defaultPath(),
					Usage:       "Full path to source code directory",
					Destination: &sourcePath,
				},
			},
			Action: func(c *cli.Context) error {
				printer.Get(print).PrintPlistResults(checkPathIsSrc(binaryPath, sourcePath))
				return nil
			},
		},
	}

	sort.Sort(cli.FlagsByName(app.Flags))
	sort.Sort(cli.CommandsByName(app.Commands))

	return app
}

func main() {
	app := getApp()

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}


