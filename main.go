package main

import (
	"errors"
	"fmt"
	"github.com/simplycubed/vulnscan/utils"
	"log"
	"os"
	"sort"

	"gopkg.in/urfave/cli.v1"

	"github.com/simplycubed/vulnscan/ios"
	"github.com/simplycubed/vulnscan/printer"
	"github.com/simplycubed/vulnscan/printer/logrus"
)

// Flags
var (
	jsonFlag = func(b *bool) cli.BoolFlag {
		return cli.BoolFlag{
			Name:        "json, j",
			Destination: b,
		}
	}
	virusFlag = func(s *string) cli.StringFlag {
		return cli.StringFlag{
			Name:        "virus, v",
			Usage:       "Activate the virus scan using Virus Total",
			Value:       "",
			Destination: s,
		}
	}
	domainCheckFlag = func(b *bool) cli.BoolFlag {
		return cli.BoolFlag{
			Name:        "domains, d",
			Usage:       "Activate the domains check at www.malwaredomainlist.com",
			Destination: b,
		}
	}
	binaryFlag = func(p *string) cli.StringFlag {
		return cli.StringFlag {
			Name:        "binary, b",
			Value:       utils.DefaultPath(),
			Usage:       "Full path to binary (ipa) file",
			Destination: p,
		}
	}
	sourceFlag = func(p *string) cli.StringFlag {
		return cli.StringFlag{
			Name:        "source, s",
			Value:       "",
			Usage:       "Full path to source code directory",
			Destination: p,
		}
	}
	appIdFlag = func(p *string) cli.StringFlag {
		return cli.StringFlag{
			Name:        "app, a",
			Value:       "",
			Usage:       "itunes app/bundle ID (i.e. com.easilydo.mail)",
			Destination: p,
		}
	}
	countryFlag = func(p *string) cli.StringFlag {
		return cli.StringFlag{
			Name:        "country, c",
			Value:       "us",
			Usage:       "store country ID (i.e. us, jp)",
			Destination: p,
		}
	}

	configurationFlag = func(p *string) cli.StringFlag {
		return cli.StringFlag{
			Name:        "Configuration, conf",
			Value:       "",
			Usage:       "scan Configuration /path/to/conf(.toml|.yaml|.json)",
			Destination: p,
		}
	}
)

// Loads the configuration and use that information to select a printer, print the message and return the printer
// to the caller. This is a quick and dirty function to avoid repetition, so we keep it in main.
func loadConfigurationAndSelectPrinter(path string, useJson bool, out logrus.Output) printer.Printer {
	confMessage := utils.LoadConfiguration(path)
	var pr printer.Printer
	// We adapt the printer to the configuration file in case output is colored.
	if out == logrus.Text || out == logrus.ColoredText {
		if utils.Configuration.ColoredLog {
			out = logrus.ColoredText
		} else {
			out = logrus.Text
		}
	}
	if useJson || utils.Configuration.JsonFormat {
		pr = logrus.NewPrinter(logrus.Json, out, logrus.DefaultFormat)
	} else {
		pr = logrus.NewPrinter(logrus.Log, out, logrus.DefaultFormat)
	}
	pr.Log(map[string]interface{}{"Message": confMessage}, nil, printer.Message)
	return pr
}

func getApp() *cli.App {
	var (
		configurationPath string

		appID             string
		country           string
		binaryPath        string
		sourcePath        string
		virusKey          string

		useJson           bool
		makeDomainCheck	  bool

	)

	app := cli.NewApp()
	app.Version = "0.0.1"
	app.Name = "vulnscan"
	app.Usage = "iOS and MacOS vulnerability scanner"
	app.Authors = []cli.Author{{ Name:  "Vulnscan Team", Email: "vulnscan@simplycubed.com" }}
	app.Copyright = "(c) 2019 SimplyCubed, LLC - Mozilla Public License 2.0"
	app.Flags = []cli.Flag{ jsonFlag(&useJson), configurationFlag(&configurationPath) }
	app.Commands = []cli.Command{

		{
			Name:    "lookup",
			Aliases: []string{"l"},
			Usage:   "store app lookup",
			Flags: []cli.Flag{ appIdFlag(&appID), countryFlag(&country) },
			Action: func(c *cli.Context) error {
				pr := loadConfigurationAndSelectPrinter(configurationPath, useJson, logrus.StdOut)
				if appID != "" {
					if country == "" {
						country = utils.Configuration.DefaultCountry
					}
					pr.Log(ios.Search(appID, country), nil, printer.Store)
				} else {
					return errors.New("appID is required: `--app appID`")
				}
				return nil
			},
		},

		{
			Name:    "plist",
			Aliases: []string{"p"},
			Usage:   "plists scan",
			Flags: []cli.Flag{ binaryFlag(&binaryPath), sourceFlag(&sourcePath) },
			Action: func(c *cli.Context) error {
				pr := loadConfigurationAndSelectPrinter(configurationPath, useJson, logrus.StdOut)
				res, err := ios.PListAnalysis(utils.CheckPathIsSrc(binaryPath, sourcePath))
				pr.Log(res, err, printer.PList)
				return nil
			},
		},

		{
			Name:    "code",
			Aliases: []string{"c"},
			Usage:   "search code vulnerabilities",
			Flags: []cli.Flag{ binaryFlag(&binaryPath), sourceFlag(&sourcePath) },
			Action: func(c *cli.Context) error {
				pr := loadConfigurationAndSelectPrinter(configurationPath, useJson, logrus.StdOut)
				p, _ := utils.CheckPathIsSrc(binaryPath, sourcePath)
				res, err := ios.CodeAnalysis(p)
				pr.Log(res, err, printer.Code)
				return nil
			},
		},

		{
			Name:    "binary",
			Aliases: []string{"b"},
			Usage:   "search binary vulnerabilities",
			Flags: []cli.Flag{ binaryFlag(&binaryPath), sourceFlag(&sourcePath) },
			Action: func(c *cli.Context) error {
				pr := loadConfigurationAndSelectPrinter(configurationPath, useJson, logrus.StdOut)
				p, s := utils.CheckPathIsSrc(binaryPath, sourcePath)
				if s { log.Fatal("Cannot make binary analysis on source code") }
				res, err := ios.BinaryAnalysis(p, s, "")
				pr.Log(res, err, printer.Binary)
				return nil
			},
		},

		{
			Name:    "scan",
			Aliases: []string{"s"},
			Usage:   "source directory and binary file security scan",
			Flags: []cli.Flag{ binaryFlag(&binaryPath), sourceFlag(&sourcePath), virusFlag(&virusKey),
							   domainCheckFlag(&makeDomainCheck),
			},
			Action: func(c *cli.Context) error {
				pr := loadConfigurationAndSelectPrinter(configurationPath, useJson, logrus.Text)

				// Overwrite the flags passed by the user
				if virusKey != "" {
					utils.Configuration.VirusScanKey = virusKey
				}
				if makeDomainCheck {
					utils.Configuration.PerformDomainCheck = true
				}
				// Check the kind of path passed by the user
				path, isSrc := utils.CheckPathIsSrc(binaryPath, sourcePath)
				// Normalize the path and call static analyzer
				if e := utils.Normalize(path, isSrc, func(p string) error {
					if e := ios.StaticAnalyzer(p, isSrc, pr); e != nil {
						return e
					}
					if e := pr.Generate(os.Stdout); e != nil {
						return e
					}
					return nil
				}); e != nil {
					fmt.Println(e)
				}
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
