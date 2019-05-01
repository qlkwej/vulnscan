# Security Bench

[![Gitter chat](https://badges.gitter.im/simplycubed/Lobby.png)](https://gitter.im/simplycubed/Lobby)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FSimplyCubed%2Fsecurity-bench.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2FSimplyCubed%2Fsecurity-bench?ref=badge_shield)
[![Build Status](https://travis-ci.org/simplycubed/security-bench.svg?branch=master)](https://travis-ci.org/simplycubed/security-bench)
[![Maintainability](https://api.codeclimate.com/v1/badges/e69d743886f1599d7c39/maintainability)](https://codeclimate.com/github/SimplyCubed/security-bench/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/e69d743886f1599d7c39/test_coverage)](https://codeclimate.com/github/SimplyCubed/security-bench/test_coverage)
[![Go Report Card](https://goreportcard.com/badge/github.com/simplycubed/security-bench)](https://goreportcard.com/report/github.com/simplycubed/security-bench)

> :warning: **WARNING**
> This project is in very early stages, it is incomplete, unstable and under rapid development.
> Expect breaking changes!

Security Bench is an opinionated static source code, binary, and configuration analyzer for iOS applications.

Written in Golang the key features and goals of the project are to provide developers with an easy to use tool which can be used as part of the local development tool chain or integrated into an automated CI/CD pipeline with smart defaults.

Smart defaults:

- **updates** - automatically check for updates
- **target directory** - the current directory is assumed unless specificied
- **target binary** - binary check is ignored unless directory path is specified
- **output** - supports text (default) and JSON formatted logs

## License

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FSimplyCubed%2Fsecurity-bench.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2FSimplyCubed%2Fsecurity-bench?ref=badge_large)
