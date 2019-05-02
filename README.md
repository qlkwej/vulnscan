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

Written in Golang with smart defaults to make it it highly portable and easy to use locally as part of the local development toolchain or integrated into an automated CI/CD process with few or no configuration.

### Smart defaults

- **updates** - automatically check for updates
- **target directory** - the current directory is assumed unless specificied
- **target binary** - binary file check is ignored unless full path is specified
- **output** - supports text (default) and JSON formatted logs

## Developing Security Bench

If you wish to work on Security Bench you'll first need Go installed on your machine (version 1.11+ is required). Confirm Go is properly installed and that a [GOPATH](https://golang.org/doc/code.html#GOPATH) has been set. You will also need to add $GOPATH/bin to your $PATH.

Next, using [Git](https://git-scm.com/), clone this repository into $GOPATH/src/github.com/simplycubed/security-bench.

Lastly, build and run the tests. If this exists with an exit status 0, and tests pass then everything is working!

```bash

cd "$GOPATH/src/github.com/simplycubed/security-bench"
go build
echo $?
go test

```

## Dependencies

Security Bench uses Go Modules and [dep](https://golang.github.io/dep/) for dependency management.

### Adding a dependency

If you're adding a dependency, you'll need to add it in the same Pull Request as the code that depends on it. This should be done in a separate commit from your code, as it makes PR review easier and Git history simpler to read in the future.

#### To add a dependency

Assuming your work is on a branch called my-feature-branch, the steps look like this:

1. Add an import statement to a suitable package in the Security Bench code.

1. Run `dep ensure` to download the latest version of the module containing the imported package into the vendor/ directory, and update the Gopkg.toml and Gopkg.lock files.

1. Review the changes in git and commit them.

### Updating a dependency

#### To update a dependency

1. Manually update the Gopkg.toml with the desired version number.

1. Run `dep ensure`

1. Review the changes in git and commit them.

## Acceptance Tests

Security Bench as a security tool will be highly dependent on having a comprehensive [acceptance test](https://en.wikipedia.org/wiki/Acceptance_testing) suite. Our [Contributing Guide](https://github.com/simplycubed/security-bench/blob/master/CONTRIBUTING.md) includes details about how and when to write and run acceptance tests in order to help contributions get accepted quickly.

## Acknowledgements

This project borrows heavily from the concepts in [OWASP Mobile Security Testing Guide](https://www.owasp.org/index.php/OWASP_Mobile_Security_Testing_Guide), [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF), and [HashiCorp's](https://github.com/hashicorp/) approach to open source projects.

## License

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FSimplyCubed%2Fsecurity-bench.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2FSimplyCubed%2Fsecurity-bench?ref=badge_large)
