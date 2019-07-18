# Vulnerability Scanner

[![Gitter chat](https://badges.gitter.im/simplycubed/Lobby.png)](https://gitter.im/simplycubed/Lobby)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fsimplycubed%2Fvulnscan.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fsimplycubed%2Fvulnscan?ref=badge_shield)
[![Build Status](https://travis-ci.org/simplycubed/vulnscan.svg?branch=master)](https://travis-ci.org/simplycubed/vulnscan)
[![codebeat badge](https://codebeat.co/badges/548c43e4-7030-4814-9732-07f6080b1f19)](https://codebeat.co/projects/github-com-simplycubed-vulnscan-master)
[![Go Report Card](https://goreportcard.com/badge/github.com/simplycubed/vulnscan)](https://goreportcard.com/report/github.com/simplycubed/vulnscan)
[![codecov](https://codecov.io/gh/simplycubed/vulnscan/branch/master/graph/badge.svg)](https://codecov.io/gh/simplycubed/vulnscan)
[![golangci](https://golangci.com/badges/github.com/simplycubed/vulnscan.svg)](https://golangci.com/r/github.com/simplycubed/vulnscan)

## :warning: **WARNING**

- This project is in very early stages, it is incomplete, unstable and under rapid development.
- Expect breaking changes!

## Overview

Vulnerability Scanner is an opinionated static source code, binary, configuration, and dependency analyzer for iOS and MacOS applications.

Written in Golang with smart defaults to make it it highly portable and easy to use locally as part of the local development toolchain or integrated into an automated CI/CD process with few or no configuration.

## Help

```bash
$ vulnscan -h

NAME:
   vulnscan - iOS and MacOS vulnerability scanner

USAGE:
   vulnscan [global options] command [command options] [arguments...]

VERSION:
   0.0.1

AUTHOR:
   Vulnscan Team <vulnscan@simplycubed.com>

COMMANDS:
     code, c    search code vulnerabilities
     lookup, l  itunes app lookup
     plist, p   plists scan
     scan, s    source directory and binary file security scan
     help, h    Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --json, -j
   --help, -h     show help
   --version, -v  print the version

COPYRIGHT:
   (c) 2019 SimplyCubed, LLC - Mozilla Public License 2.0

```

## VirusTotal scan

- VirusToal is an optional vulnerability scan which requires registering a free account on [VirusTotal.com](https://www.virustotal.com/gui/join-us) and agreeing to their Terms of Service and Privacy Policy. Once your account is created you will receive an API key which is required when running the scan.
- **Important** using this scan will send VirusTotal.com a copy of your binary file for analysis.

One you receive your API key please create a `.env` file within the same directory as Vulnscan is installed.

```bash

# .env file

VIRUS_TOTAL_API_KEY=<API key from VirusTotal Profile>

```


### Country Codes

- A complete list of [iTunes supported country codes](https://github.com/simplycubed/vulnscan/blob/master/ITUNES_COUNTRY_CODES)

## Developing Vulnerability Scanner

If you wish to work on Vulnerability Scanner you'll first need Go installed on your machine (version 1.11+ is required). Confirm Go is properly installed and that a [GOPATH](https://golang.org/doc/code.html#GOPATH) has been set. You will also need to add $GOPATH/bin to your $PATH.

Next, using [Git](https://git-scm.com/), clone this repository into $GOPATH/src/github.com/simplycubed/vulnscan.

Lastly, build and run the tests. If this exists with an exit status 0, and tests pass then everything is working!

```bash

cd "$GOPATH/src/github.com/simplycubed/vulnscan"
go build
echo $?
go test ./...

```

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

## License

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fsimplycubed%2Fvulnscan.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fsimplycubed%2Fvulnscan?ref=badge_large)
