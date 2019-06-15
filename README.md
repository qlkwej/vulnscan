# Vulnerability Scanner

[![Gitter chat](https://badges.gitter.im/simplycubed/Lobby.png)](https://gitter.im/simplycubed/Lobby)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FSimplyCubed%2Fvulnscan.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2FSimplyCubed%2Fvulnscan?ref=badge_shield)
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
   Vulnerability Scanner - iOS and MacOS vulnerability scanner

USAGE:
   vulnscan [global options] command [command options] [arguments...]

VERSION:
   0.0.1

AUTHOR:
   Engineering <info@simplycubed.com>

COMMANDS:
     lookup, l  itunes lookup
     scan, s    source code vulnerability scaning
     help, h    Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h     show help
   --version, -v  print the version

COPYRIGHT:
   (c) 2019 SimplyCubed, LLC - Mozilla Public License 2.0

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
go test

```

## Dependencies

Vulnerability Scanner uses Go Modules and [dep](https://golang.github.io/dep/) for dependency management.

### Adding a dependency

If you're adding a dependency, you'll need to add it in the same Pull Request as the code that depends on it. This should be done in a separate commit from your code, as it makes PR review easier and Git history simpler to read in the future.

#### To add a dependency

Assuming your work is on a branch called my-feature-branch, the steps look like this:

1. Add an import statement to a suitable package in the Vulnerability Scanner code.

1. Run `dep ensure` to download the latest version of the module containing the imported package into the vendor/ directory, and update the Gopkg.toml and Gopkg.lock files.

1. Review the changes in git and commit them.

### Updating a dependency

#### To update a dependency

1. Manually update the Gopkg.toml with the desired version number.

1. Run `dep ensure`

1. Review the changes in git and commit them.

## Acceptance Tests

Vulnerability Scanner as a security tool will be highly dependent on having a comprehensive [acceptance test](https://en.wikipedia.org/wiki/Acceptance_testing) suite. Our [Contributing Guide](https://github.com/simplycubed/vulnscan/blob/master/.github/CONTRIBUTING.md) includes details about how and when to write and run acceptance tests in order to help contributions get accepted quickly.

## Acknowledgements

This project borrows heavily from the concepts in [OWASP Mobile Security Testing Guide](https://www.owasp.org/index.php/OWASP_Mobile_Security_Testing_Guide) and [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF). It's also based on my understanding of [HashiCorp's](https://github.com/hashicorp/) approach to open source projects.

## License

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fsimplycubed%2Fvulnscan.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fsimplycubed%2Fvulnscan?ref=badge_shield)
