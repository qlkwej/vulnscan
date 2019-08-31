package output

import (
	"fmt"
	"github.com/simplycubed/vulnscan/entities"
	"io"
	"io/ioutil"
	"log"
)

type BasicLogger struct {
	Info    *log.Logger
	Warning *log.Logger
	Error   *log.Logger
}

var basicLogger *BasicLogger

func BasicLoggerAdapter(command entities.Command, entity *entities.LogMessage) error {
	if basicLogger == nil {
		return fmt.Errorf("logger not initializated")
	}
	var message string
	if entity.Analysis == entities.None {
		message = entity.Message
	} else {
		message = fmt.Sprintf("%s: %s", entity.Analysis, entity.Message)
	}
	switch entity.Level {
	case entities.Inf:
		basicLogger.Info.Println(message)
	case entities.Warn:
		basicLogger.Warning.Println(message)
	case entities.Err:
		basicLogger.Error.Println(message)
	}
	return nil
}

// SetLogger sets the logging level preference
func SetBasicLogger(out io.Writer, level entities.LogLevel, logTime bool) {
	initLog := func(infoOut io.Writer, warningOut io.Writer, errorOut io.Writer) {
		flag := 0
		if logTime {
			flag = log.Ltime
		}
		basicLogger = &BasicLogger{
			Info:    log.New(infoOut, "INFO| ", flag),
			Warning: log.New(warningOut, "WARNING| ", flag),
			Error:   log.New(errorOut, "ERROR| ", flag),
		}
	}
	switch level {
	case entities.Inf:
		initLog(out, out, out)
	case entities.Warn:
		initLog(ioutil.Discard, out, out)
	case entities.Err:
		initLog(ioutil.Discard, ioutil.Discard, out)
	default:
		initLog(ioutil.Discard, ioutil.Discard, ioutil.Discard)
	}
}
