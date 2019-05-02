package main

import (
	"log"
	"os"
	"sort"

	"gopkg.in/urfave/cli.v1"
)

func main() {
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
			Name:  "source, s",
			Value: ".",
			Usage: "Full path to source code directory",
		},
		cli.StringFlag{
			Name:  "binary, b",
			Usage: "Full path to binary file",
		},
		cli.StringFlag{
			Name:  "output format",
			Value: "terminal",
			Usage: "Output format (terminal, json)",
		},
	}

	app.EnableBashCompletion = true

	sort.Sort(cli.FlagsByName(app.Flags))
	sort.Sort(cli.CommandsByName(app.Commands))

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
