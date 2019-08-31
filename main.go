package main

import (
	"fmt"
	"log"
	"os"
	"sort"

	"gopkg.in/urfave/cli.v1"

	"github.com/simplycubed/vulnscan/adapters"
	"github.com/simplycubed/vulnscan/adapters/input"
	"github.com/simplycubed/vulnscan/adapters/output"
	"github.com/simplycubed/vulnscan/adapters/services"
	"github.com/simplycubed/vulnscan/adapters/tools"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/usecases/binary"
	"github.com/simplycubed/vulnscan/usecases/code"
	"github.com/simplycubed/vulnscan/usecases/files"
	"github.com/simplycubed/vulnscan/usecases/plist"
	"github.com/simplycubed/vulnscan/usecases/static"
	"github.com/simplycubed/vulnscan/usecases/store"
)

const (
	jtoolRoute = "https://github.com/simplycubed/vulnscan-dependencies/releases/download/0.0.1-beta/jtool"
	classDumpZRoute = "https://github.com/simplycubed/vulnscan-dependencies/releases/download/0.0.1-beta/class-dump-z"
	classDumpSwiftRoute = "https://github.com/simplycubed/vulnscan-dependencies/releases/download/0.0.1-beta/class-dump-swift"
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
		return cli.StringFlag{
			Name:        "binary, b",
			Value: 		 func() string {
				dir, _ := os.Getwd()
				return dir
			}(),
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


func getApp() *cli.App {
	var (
		configurationPath string

		appID      string
		country    string
		binaryPath string
		sourcePath string
		virusKey   string

		useJSON         bool
		makeDomainCheck bool

		applicationFlags = []cli.Flag{jsonFlag(&useJSON), configurationFlag(&configurationPath)}

		command = entities.Command{
			Output:        os.Stdout,
		}

		adapter = adapters.AdapterMap{
			Services: adapters.ServiceAdapters {
				MalwareDomains: nil,
				VirusScan:      nil,
			},
			Tools: adapters.ToolAdapters {
				ClassDump: tools.JtoolClassDumpAdapter,
				Libs:      tools.JtoolLibsAdapter,
				Headers:   tools.JtoolHeadersAdapter,
				Symbols:   tools.JtoolSymbolsAdapter,
			},
			Output: adapters.OutputAdapters {
				Logger: output.BasicLoggerAdapter,
				Result: output.PrettyConsoleAdapter,
				Error:  output.BasicErrorAdapter,
			},
		}

		parseConfiguration = func() {
			input.ConfigurationAdapter(entities.Command{Path: configurationPath}, &command, &adapter)
			if len(appID) > 0 {
				command.AppId = appID
			}
			if len(country) > 0 {
				command.Country = country
			}
			// For now all we have is binary analysis. When we have a mix of binary and source analysis,
			// we will just include two paths in the command entity.
			if len(binaryPath) > 0 {
				command.Path = binaryPath
			} else {
				command.Path = sourcePath
				command.Source = true
			}
			if makeDomainCheck {
				adapter.Services.MalwareDomains = services.MalwareDomainsAdapter
			}
			if len(virusKey) > 0 {
				command.VirusTotalKey = virusKey
				adapter.Services.VirusScan = services.VirusTotalAdapter
			}
			if useJSON {
				adapter.Output.Result = output.JsonAdapter
			}
			if ves := command.Validate(); len(ves) > 0 {
				log.Fatal(fmt.Sprintf("Invalid generated command, validation errors: %s", fmt.Sprintf("%s", ves)))
			}
		}
	)

	app := cli.NewApp()
	app.Version = "0.0.1"
	app.Name = "vulnscan"
	app.Usage = "iOS and MacOS vulnerability scanner"
	app.Authors = []cli.Author{{Name: "Vulnscan Team", Email: "vulnscan@simplycubed.com"}}
	app.Copyright = "(c) 2019 SimplyCubed, LLC - Mozilla Public License 2.0"
	app.Commands = []cli.Command{
		{
			Name:    "lookup",
			Aliases: []string{"l"},
			Usage:   "store app lookup",
			Flags:   append(applicationFlags, []cli.Flag{appIdFlag(&appID), countryFlag(&country)}...),
			Action: func(c *cli.Context) error {
				parseConfiguration()
				store.Analysis(command, &entities.StoreAnalysis{}, adapter)
				return nil
			},
		},
		{
			Name:    "plist",
			Aliases: []string{"p"},
			Usage:   "plists scan",
			Flags:   append(applicationFlags, []cli.Flag{binaryFlag(&binaryPath), sourceFlag(&sourcePath)}...),
			Action: func(c *cli.Context) error {
				parseConfiguration()
				plist.Analysis(command, &entities.PListAnalysis{}, adapter)
				return nil
			},
		},
		{
			Name:    "code",
			Aliases: []string{"c"},
			Usage:   "search code vulnerabilities",
			Flags:   append(applicationFlags, []cli.Flag{binaryFlag(&binaryPath), sourceFlag(&sourcePath)}...),
			Action: func(c *cli.Context) error {
				parseConfiguration()
				code.Analysis(command, &entities.CodeAnalysis{}, adapter)
				return nil
			},
		},
		{
			Name:    "binary",
			Aliases: []string{"b"},
			Usage:   "search binary vulnerabilities",
			Flags:   append(applicationFlags, []cli.Flag{binaryFlag(&binaryPath), sourceFlag(&sourcePath)}...),
			Action: func(c *cli.Context) error {
				parseConfiguration()
				binary.Analysis(command, &entities.BinaryAnalysis{}, adapter)
				return nil
			},
		},
		{
			Name: "files",
			Aliases: []string{"f"},
			Usage: "lookup and clasify files",
			Flags: append(applicationFlags, []cli.Flag{binaryFlag(&binaryPath), sourceFlag(&sourcePath)}...),
			Action: func(c *cli.Context) error {
				parseConfiguration()
				files.Analysis(command, &entities.FileAnalysis{}, adapter)
				return nil
			},
		},
		{
			Name:    "scan",
			Aliases: []string{"s"},
			Usage:   "source directory and binary file security scan",
			Flags: append(applicationFlags, []cli.Flag{
				binaryFlag(&binaryPath),
				sourceFlag(&sourcePath),
				virusFlag(&virusKey),
				domainCheckFlag(&makeDomainCheck)}...
			),
			Action: func(c *cli.Context) error {
				parseConfiguration()
				static.Analysis(command, &entities.StaticAnalysis{}, adapter)
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
