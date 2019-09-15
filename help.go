package main

import "fmt"

var appHelp = fmt.Sprintf(`NAME:
   {{.Name}} - {{.Usage}}

USAGE:
   {{.HelpName}} {{if .Commands}}[command] [options]{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}[arguments...]{{end}}
   {{if len .Authors}}
AUTHOR:
   {{range .Authors}}{{ . }}{{end}}
   {{end}}{{if .Commands}}
COMMANDS:
{{range .Commands}}{{if not .HideHelp}}   {{join .Names ", "}}{{ "\t"}}{{.Usage}}{{ "\n" }}{{end}}{{end}}{{end}}{{if .VisibleFlags}}
GLOBAL OPTIONS:
   Without command:
   {{range .VisibleFlags}}{{.}}
   {{end}}With command:
   --help, -h	print the command help
   --json, -j	outputs as json, instead of console format
   --configuration, -c 	+ /path/to/conf(.toml|.yaml|.json), scan the configuration file 
   --tools, -t	+ /path/to/tools, folder where the external tools are / should be downloaded
   --quiet, -q 	do not log info messages
{{end}}{{if .Copyright }}
COPYRIGHT:
   {{.Copyright}}
   {{end}}{{if .Version}}
VERSION:
   {{.Version}}
   {{end}}
`)
