![vulnscan](/vulnscan.png)

# Vulnscan (Vulnerability Scanner)

[![Gitter chat](https://badges.gitter.im/simplycubed/Lobby.png)](https://gitter.im/simplycubed/Lobby)
[![codecov](https://codecov.io/gh/simplycubed/vulnscan/branch/master/graph/badge.svg)](https://codecov.io/gh/simplycubed/vulnscan)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fsimplycubed%2Fvulnscan.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fsimplycubed%2Fvulnscan?ref=badge_shield)
[![Build Status](https://travis-ci.org/simplycubed/vulnscan.svg?branch=master)](https://travis-ci.org/simplycubed/vulnscan)
[![golangci](https://golangci.com/badges/github.com/simplycubed/vulnscan.svg)](https://golangci.com/r/github.com/simplycubed/vulnscan)

## :white_check_mark: **Vulnscan v0.2.0 released!**

- [Download](https://github.com/simplycubed/vulnscan/releases/tag/v0.2.0)
- This project is still in very early stages, it is incompelte, unstable, and under rapid development.
- At the same time, it would be great to get feedback, feature requests, and most importantly bug reports.

## Overview

Vulnscan is an opinionated static source code, binary, configuration, and dependency analyzer for iOS and macOS applications.

Written in Golang with smart defaults to make it it highly portable and easy to use locally as part of the local development toolchain or integrated into an automated CI/CD process with few or no configuration.

## Documentation

How-to's and more information has been moved to the [wiki](https://github.com/simplycubed/vulnscan/wiki).

## Help

```bash
$ vulnscan -h

NAME:
   vulnscan - iOS and macOS vulnerability scanner

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

## Acknowledgements

This project borrows heavily from the concepts in [OWASP Mobile Security Testing Guide](https://www.owasp.org/index.php/OWASP_Mobile_Security_Testing_Guide) and [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF). It's also based on our understanding of [HashiCorp's](https://github.com/hashicorp/) approach to open source projects.

## Contributors

A special thanks to the following members. They have made a significant contribution to the development and release of Vulnscan.

- [José González, @joseincandenza](https://github.com/joseincandenza)

## License

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fsimplycubed%2Fvulnscan.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fsimplycubed%2Fvulnscan?ref=badge_large)
