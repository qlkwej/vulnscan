package main

import (
	"log"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/urfave/cli.v1"
)

func main() {

	var sourcePath string
	var binaryPath string
	var outputFormat string

	app := cli.NewApp()
	app.Version = "0.0.1"
	app.Authors = []cli.Author{
		cli.Author{
			Name:  "Charles @ SimplyCubed",
			Email: "info@simplycubed.com",
		},
	}
	app.Copyright = "(c) 2019 SimplyCubed, LLC - Mozilla Public License 2.0"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "source, s",
			Value:       getExecutionPath(),
			Usage:       "Full path to source code directory",
			Destination: &sourcePath,
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
		if isValidPath(sourcePath) {
			log.Print(sourcePath)
			log.Print("True")
		} else {
			log.Print(sourcePath)
			log.Print("False")
		}

		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func getExecutionPath() string {
	dir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	return dir
}

func isValidPath(path string) bool {
	if v, err := os.Stat(path); os.IsNotExist(err) {
		log.Print(v)

		if err != nil {
			log.Fatal(path)
			return false
		}
	}
	return true
}
