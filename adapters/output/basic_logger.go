package output

import (
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
	"io"
	"io/ioutil"
	"log"
	"os"
)


type BasicLogger struct {
	Info    *log.Logger
	Warning *log.Logger
	Error   *log.Logger
}

var basicLogger *BasicLogger


// SetLogger sets the logging level preference
func SetLogger(level entities.LogLevel, logTime bool) {
	initLog := func(infoHandle io.Writer, warningHandle io.Writer, errorHandle io.Writer) {
		flag := 0
		if logTime {
			flag = log.Ltime
		}
		basicLogger = &BasicLogger{
			Info:    log.New(infoHandle, "INFO: ", flag),
			Warning: log.New(warningHandle, "WARNING: ", flag),
			Error:   log.New(errorHandle, "ERROR: ", flag),
		}
	}
	switch level {
	case entities.I:
		initLog(os.Stderr, os.Stderr, os.Stderr)
	case entities.W:
		initLog(ioutil.Discard, os.Stderr, os.Stderr)
	case entities.E:
		initLog(ioutil.Discard, ioutil.Discard, os.Stderr)
	default:
		initLog(ioutil.Discard, ioutil.Discard, ioutil.Discard)
	}
}


func BasicLoggerAdapter(command utils.Command, entity *entities.LogMessage) (entities.Entity, error) {
	switch entity.Level {
	case entities.I:
		basicLogger.Info.Println(entity.Message)
	case entities.W:
		basicLogger.Warning.Println(entity.Message)
	case entities.E:
		basicLogger.Error.Println(entity.Message)
	}
	return entity, nil
}
