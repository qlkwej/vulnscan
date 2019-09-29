# Vulnerability Scanner

[![Gitter chat](https://badges.gitter.im/simplycubed/Lobby.png)](https://gitter.im/simplycubed/Lobby)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/acb61eca797b46e099005f2a39f0e6ba)](https://www.codacy.com/manual/SimplyCubed/vulnscan?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=simplycubed/vulnscan&amp;utm_campaign=Badge_Grade)
[![Codacy Badge](https://api.codacy.com/project/badge/Coverage/acb61eca797b46e099005f2a39f0e6ba)](https://www.codacy.com?utm_source=github.com&utm_medium=referral&utm_content=simplycubed/vulnscan&utm_campaign=Badge_Coverage)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fsimplycubed%2Fvulnscan.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fsimplycubed%2Fvulnscan?ref=badge_shield)
[![Build Status](https://travis-ci.org/simplycubed/vulnscan.svg?branch=master)](https://travis-ci.org/simplycubed/vulnscan)
[![golangci](https://golangci.com/badges/github.com/simplycubed/vulnscan.svg)](https://golangci.com/r/github.com/simplycubed/vulnscan)

## :white_check_mark: **Release v0.2.0 released!**

- [Vulnscan v0.2.0 - Release](https://github.com/simplycubed/vulnscan/releases/tag/v0.2.0)
- This project is still in very early stages, it is incompelte, unstable, and under rapid development.
- At the same time, it would be great to get feedback, feature requests, and most importantly bug reports.

## Overview

Vulnerability Scanner is an opinionated static source code, binary, configuration, and dependency analyzer for iOS and MacOS applications.

Written in Golang with smart defaults to make it it highly portable and easy to use locally as part of the local development toolchain or integrated into an automated CI/CD process with few or no configuration.

## Commands

Each of the commands can be called using its full name or its abreviation letter.

### lookup (l)

__Description:__

Search information about the application in the appstore.

__Specific flags__:

`--app/-a`: string flag, itunes app/bundle ID. Required to make the search using this command.

```bash
Usage example: -a com.easilydo.mail
```

`--country, --ct`: the country code to make the lookup. It defaults to "us". You can check [here a complete list of iTunes supported country codes](https://github.com/simplycubed/vulnscan/blob/master/ITUNES_COUNTRY_CODES).

```bash
Usage example: --ct fr
```

### plist (p)

__Description__:

Extracts information from the application plist file, like permissions or insecure connections.

__Specific flags__:

`--binary/-b`: full path to the application binary file (.ipa/.app). Required if source flag is not provided.

```bash
Usage example: -b /path/to/binary.ipa
```

`--source/-s`: full path to the application source code folder. Required if binary flag is not provided.

> Note: if both binary and source paths are defined, the binary path takes preference.

```bash
Usage example: -s /path/to/source_code
```

### files (f)

__Description__:

General review of the files found on the application. Looks for databases, plist files or certification files.

__Specific flags__:

`--binary/-b`: full path to the application binary file (.ipa/.app). Required if source flag is not provided.

```bash
Usage example: -b /path/to/binary.ipa
```

`--source/-s`: full path to the application source code folder. Required if binary flag is not provided.

> Note: if both binary and source paths are defined, the binary path takes preference.

```bash
Usage example: -s /path/to/source_code
```

### binary (b)

__Description__:

Extracts binary information like libraries used, macho files information or vulnerabilities.

> This command requires the use of external tools. See the download command for instructions on how to get them.

__Specific flags__:

`--binary/-b`: full path to the application binary file (.ipa/.app). Required if source flag is not provided.

```bash
Usage example: -b /path/to/binary.ipa
```

`--source/-s`: full path to the application source code folder. Required if binary flag is not provided.

> Note: if both binary and source paths are defined, the binary path would take preference.

```bash
Usage example: -s /path/to/source_code
```

### code (c)

__Description__:

Search for static code vulnerabilities, apis used and embedded urls or emails. Optionally, it can
check if the urls embedded belong to malware domains (see domains flag.)

__Specific flags__:

`--binary/-b`: full path to the application binary file (.ipa/.app). Required if source flag is
not provided.

```bash
Usage example: -b /path/to/binary.ipa
```

`--source/-s`: full path to the application source code folder. Required if binary flag is not provided.

```bash
Usage example: -s /path/to/source_code
```

`--domains/-d`: whether or not check malware domains.

> Note: if both binary and source paths are defined, the binary path takes preference.

```bash
Usage example: -d
```

### virus (v)

__Description__:

Search the binary for virus using the virus total API.

__Notes on usage__:

This is an optional vulnerability scan which requires registering a free account on [VirusTotal.com](https://www.virustotal.com/gui/join-us) and agreeing to their Terms of Service and Privacy Policy. Once your account is created you will receive an API key which is required when running the scan.

> __Important__: using this scan will send VirusTotal.com a copy of your binary file for analysis.

__Specific flags__:

`--binary/-b`: full path to the application binary file (.ipa/.app). Required if source flag is not provided.

```bash
Usage example: -b /path/to/binary.ipa
```

`--virus/-v`: API key required by the VirusTotal service.

### scan (s)

__Description__:

Performs all the analysis. VirusTotal API use and malware domain check services are optional
using the provided flags (if the VirusTotal API key is not passed, the analysis is just skipped).
Those analysis that can be performed only on binary input (VirusTotal service and binary analysis)
won't run if only a source path is provided.

__Specific flags__:

`--binary/-b`: full path to the application binary file (.ipa/.app). Required if source flag is
not provided. Usage example: -b /path/to/binary.ipa

`--source/-s`: full path to the application source code folder. Required if binary flag is not provided.

```bash
Usage example: -s /path/to/source_code
```

`--virus/-v`: API key required by the VirusTotal service.

```bash
Usage example: -v xxdad0adadadslkadasdadadsasdade9ad09f
```

`--domains/-d`: whether or not check malware domains.

```bash
Usage example: -d
```

### download (d)

__Description__:

Downloads the external tools required to run the binary analysis. By default, these tools
are downloaded on the same folder where the application binary is located, and will be loaded
from there when the analysis is run. The user may pass an alternative location to download/use
these tools.

## Global flags

`--json/-j`: By default, the application will output to stdout a printable and human readable
report of the analysis results. The user may use this flag to output a machine readable json
instead, specially useful for CI solutions ingestion.

```bash
Usage example: -j
```

`--tools/-t`: Optional flag containing the folder where the external tools needed
to perform the binary analysis are located. When used with the download command, this flag is
used to determine where the tools are downloaded.

```bash
Usage example: -t /path/to/tools
```

`--configuration/-c`: Path to an optional configuration file to change the default behaviour of the
program. See the configuration section for more information.

`--quiet/-q`: By default, the program logs information about execution to stderr. Passing this
flag, only warnings and error will be logged.

## Configuration

Almost every vulnscan behaviour can be adapted passing command line flags. But other times, it's
more convenient to use a configuration file to alter the behaviour in a more permanent way. Vulnscan
provides this ability, using three common formats: TOML, YAML and JSON.

The configuration file location may be passed as a flag. But the program can identify it automatically
two, if it's located either in the current working directory or in the folder where the vulnscan
binary is. For this to happen, the file shall have the name "`vulnscan`" and one of the accepted file
extensions (`.json`, `.yaml` or `.toml`).

Here is an example of each one of this formats using every option available:

```json
{
  "scans":  ["binary", "code", "plist"],
  "json": true,
  "binary": "route/to/binary.ipa",
  "source": "route/to/source",
  "tools": "tools/folder",
  "virus": "virus_scan_password",
  "country": "es",
  "quiet": true,
  "domains": true
}
```

```yaml
scans: [binary, code, plist]
json: true
binary: route/to/binary.ipa
source: route/to/source
tools: tools/folder
virus: virus_scan_password
country: es
quiet: true
domains: true
```

```toml
scans = ["binary", "code", "plist"]
json = true
binary = "route/to/binary.ipa"
source = "route/to/source"
tools = "tools/folder"
virus = "virus_scan_password"
country = "es"
quiet = true
domains = true
```

### Available options

- __scans__: array[string], scans to do in case of running a complete scan
- __json__: boolean, whether or not output using json format
- __binary__: string, route to the binary to analyze
- __source__: string, route to the source code to analyze
- __tools__: string, path to the tools folder
- __virus__: string, VirusTotal key
- __country__: string, country to use for appstore app lookup
- __quiet__: boolean, whether or not run using quiet mode
- __domains__: booean, whether or not run malware domains check (for code and scan commands)

## Help

```bash
$ vulnscan -h

NAME:
   vulnscan - iOS and MacOS vulnerability scanner

USAGE:
   app [global options] command [command options] [arguments...]

VERSION:
   0.2.0

AUTHOR:
   Vulnscan Team <vulnscan@simplycubed.com>

COMMANDS:
     binary, b    search binary vulnerabilities
     code, c      search code vulnerabilities
     download, d  downloads the external tools used by vulnscan to work
     files, f     lookup and clasify files
     lookup, l    store app lookup
     plist, p     plists scan
     scan, s      source directory and binary file security scan
     virus, v     performs a virus analysis using the VirusTotal API
     help, h      Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h     show help
   --version, -v  print the version

COPYRIGHT:
   (c) 2019 SimplyCubed, LLC - Mozilla Public License 2.0

```

## Developing Vulnscan

If you wish to work on Vulnscan you'll first need Go installed on your machine (version 1.11+ is required). Confirm Go is properly installed and that a [GOPATH](https://golang.org/doc/code.html#GOPATH) has been set. You will also need to add $GOPATH/bin to your $PATH.

Next, using [Git](https://git-scm.com/), clone this repository. The recursive flag is necessary in order to download the git submodules with the tools and the test files. Without it, you won't be able to run the tests.

```bash
git clone https://github.com/simplycubed/vulnscan --recursive
```

Lastly, build and run the tests. If this exits with an exit status 0, and tests pass then everything is working!

```bash

cd "$GOPATH/src/github.com/simplycubed/vulnscan"
go build
echo $?
go test ./...

```

## Clean Architecture

Vulnscan is build using the concepts of Clean Architecture as defined by [Uncle Bob - The Clean Code Blog](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html).

> Each of these architectures produce systems that are:
>
> 1. Independent of Frameworks. The architecture does not depend on the existence of some library of feature laden software. This allows you to use such frameworks as tools, rather than having to cram your system into their limited constraints.
> 1. Testable. The business rules can be tested without the UI, Database, Web Server, or any other external element.
> 1. Independent of UI. The UI can change easily, without changing the rest of the system. A Web UI could be replaced with a console UI, for example, without changing the business rules.
> 1. Independent of Database. You can swap out Oracle or SQL Server, for Mongo, BigTable, CouchDB, or something else. Your business rules are not bound to the database.
> 1. Independent of any external agency. In fact your business rules simply don’t know anything at all about the outside world.

This translates into the following layers within Vulnscan:

1. Entities: Structs implementing the results of different types of analysis.
2. Usecases: These would be the methods needed to fulfill the entities (i.e. the analysis themselves).
3. Adapters: functions to interact with the external world (external tools and services).
4. Frameworks: basically, the interaction with the CLI.

## Dependencies

Vulnerability Scanner uses Go Modules for dependency management.

### Adding a dependency

If you're adding a dependency, you'll need to add it in the same Pull Request as the code that depends on it. This should be done in a separate commit from your code, as it makes PR review easier and Git history simpler to read in the future.

#### To add a dependency

Assuming your work is on a branch called my-feature-branch, the steps look like this:

1. Add an import statement to a suitable package in the Vulnerability Scanner code.
1. Review the changes in git and commit them.

## Acceptance Tests

Vulnerability Scanner as a security tool will be highly dependent on having a comprehensive [acceptance test](https://en.wikipedia.org/wiki/Acceptance_testing) suite. Our [Contributing Guide](https://github.com/simplycubed/vulnscan/blob/master/.github/CONTRIBUTING.md) includes details about how and when to write and run acceptance tests in order to help contributions get accepted quickly.

## Acknowledgements

This project borrows heavily from the concepts in [OWASP Mobile Security Testing Guide](https://www.owasp.org/index.php/OWASP_Mobile_Security_Testing_Guide) and [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF). It's also based on our understanding of [HashiCorp's](https://github.com/hashicorp/) approach to open source projects.

## Contributors

A special thanks to the following members. They have made a significant contribution to the development and release of Vulnscan.

- [José González, @joseincandenza](https://github.com/joseincandenza)

## License

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fsimplycubed%2Fvulnscan.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fsimplycubed%2Fvulnscan?ref=badge_large)
