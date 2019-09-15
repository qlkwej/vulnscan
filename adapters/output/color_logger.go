package output

import (
	"fmt"
	"github.com/simplycubed/vulnscan/entities"
	"io"
	"io/ioutil"
	"log"
)

var colorMap = map[string]string{
	"off":    "\033[0m",
	"red":    "\033[0;31m",
	"green":  "\033[0;32m",
	"orange": "\033[0;33m",
	"blue":   "\033[0;34m",
	"purple": "\033[0;35m",
	"cyan":   "\033[0;36m",
	"gray":   "\033[0;37m",
}

func SetColorLogger(out io.Writer, level entities.LogLevel, logTime bool) {
	initLog := func(infoOut io.Writer, warningOut io.Writer, errorOut io.Writer) {
		flag := 0
		if logTime {
			flag = log.Ltime
		}
		basicLogger = &BasicLogger{
			Info:    log.New(infoOut, fmt.Sprintf("%sINFO| %s", colorMap["blue"], colorMap["off"]), flag),
			Warning: log.New(warningOut, fmt.Sprintf("%sWARNING| %s", colorMap["orange"], colorMap["off"]), flag),
			Error:   log.New(errorOut, fmt.Sprintf("%sERROR| %s", colorMap["red"], colorMap["off"]), flag),
		}
	}
	switch level {
	case entities.Info:
		initLog(out, out, out)
	case entities.Warn:
		initLog(ioutil.Discard, out, out)
	case entities.Err:
		initLog(ioutil.Discard, ioutil.Discard, out)
	default:
		initLog(ioutil.Discard, ioutil.Discard, ioutil.Discard)
	}
}
