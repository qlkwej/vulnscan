# Security Bench

[![Gitter chat](https://badges.gitter.im/simplycubed/Lobby.png)](https://gitter.im/simplycubed/Lobby)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FSimplyCubed%2Fsecurity-bench.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2FSimplyCubed%2Fsecurity-bench?ref=badge_shield)
[![Build Status](https://travis-ci.org/simplycubed/security-bench.svg?branch=master)](https://travis-ci.org/simplycubed/security-bench)
[![codebeat badge](https://codebeat.co/badges/548c43e4-7030-4814-9732-07f6080b1f19)](https://codebeat.co/projects/github-com-simplycubed-security-bench-master)
[![Go Report Card](https://goreportcard.com/badge/github.com/simplycubed/security-bench)](https://goreportcard.com/report/github.com/simplycubed/security-bench)
[![codecov](https://codecov.io/gh/simplycubed/security-bench/branch/master/graph/badge.svg)](https://codecov.io/gh/simplycubed/security-bench)
[![golangci](https://golangci.com/badges/github.com/simplycubed/security-bench.svg)](https://golangci.com/r/github.com/simplycubed/security-bench)

## :warning: **WARNING**

- This project is in very early stages, it is incomplete, unstable and under rapid development.
- Expect breaking changes!

## Overview

Security Bench is an opinionated static source code, binary, configuration, and dependency analyzer for iOS and MacOS applications.

Written in Golang with smart defaults to make it it highly portable and easy to use locally as part of the local development toolchain or integrated into an automated CI/CD process.

### Smart defaults

- **updates** - automatically check for updates
- **target directory** - the current directory is assumed unless specificied
- **target binary** - binary check is ignored unless directory path is specified
- **output** - supports text (default) and JSON formatted logs

## Developing Security Bench

If you wish to work on Security Bench you'll first need Go installed on your machine (version 1.11+ is required). Confirm Go is properly installed and that a GOPATH has been set. You will also need to add $GOPATH/bin to your $PATH.

Next, using Git, clone this repository into $GOPATH/src/github.com/simplycubed/security-bench.

Lastly, build and run the tests. If this exists with an exit status 0, and tests pass then everything is working!

```bash

cd "$GOPATH/src/github.com/simplycubed/security-bench"
go build
echo $?
go test

```

## Dependencies

Security Bench uses Go Modules and [dep](https://golang.github.io/dep/) for dependency management.


## License

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FSimplyCubed%2Fsecurity-bench.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2FSimplyCubed%2Fsecurity-bench?ref=badge_large)
