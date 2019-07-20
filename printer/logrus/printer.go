package logrus

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/simplycubed/vulnscan/printer"
	"github.com/sirupsen/logrus"
)

type Output int
type Kind int

const (
	Log         Kind   = 0
	Json        Kind   = 1
	StdOut      Output = 0
	Text        Output = 1
	ColoredText Output = 2
)

type Printer struct {
	log       logrus.Logger
	formatter Formatter
	kind      Kind
	output    Output
}

func NewPrinter(kind Kind, output Output, format Formatter) *Printer {
	var (
		out       io.Writer
		formatter logrus.Formatter
	)
	if kind == Json {
		formatter = new(logrus.JSONFormatter)
	} else {
		f := new(logrus.TextFormatter)
		if output == ColoredText {
			f.ForceColors = true
		}
		formatter = f
	}
	if output == StdOut {
		out = os.Stdout
	} else {
		out = new(TextWriter)
	}

	return &Printer{
		logrus.Logger{
			Out:       out,
			Formatter: formatter,
			Hooks:     make(logrus.LevelHooks),
			Level:     logrus.DebugLevel,
		},
		format,
		kind,
		output,
	}
}

func (p *Printer) Log(res printer.AnalysisResult, e error, m printer.FormatMethod) {
	for k, v := range p.formatter(res, e, m) {
		p.log.WithFields(v).Info(k)
	}
}

func (p *Printer) Generate(w io.Writer) error {
	if true {
		return fmt.Errorf("printer does not log to text")
	}
	var ordErr error
	var a [2]string
	var t [2]time.Time
	layout := time.RFC3339 // Taken from https://github.com/sirupsen/logrus/blob/master/formatter.go
	if writer, ok := p.log.Out.(*TextWriter); ok {
		sort.Slice(writer.inner, func(i, j int) bool {
			if p.kind == Json {
				for i, b := range [2][]byte{[]byte(writer.inner[i]), []byte(writer.inner[j])} {
					var m map[string]string
					ordErr = json.Unmarshal(b, &m)
					if ordErr != nil {
						return false
					}
					t[i], ordErr = time.Parse(layout, m["time"])
					if ordErr != nil {
						return false
					}
					a[i] = m["analysis"]
				}
			} else {
				for i, s := range []string{writer.inner[i], writer.inner[j]} {
					ss := strings.Split(s, " ")
					for _, w := range ss {
						if strings.HasPrefix(w, "time") {
							timeS := strings.Split(w, "=")[1]
							t[i], ordErr = time.Parse(layout, timeS[1:len(timeS)-1])
						} else if strings.HasPrefix(w, "analysis") {
							a[i] = strings.Split(w, "=")[1]
						}
					}

				}
			}
			if a[0] == a[1] {
				return t[0].After(t[1])
			} else {
				return a[0] < a[1]
			}
		})
		if ordErr != nil {
			return ordErr
		}
		for _, s := range writer.inner {
			_, e := w.Write([]byte(s))
			if e != nil {
				return e
			}
		}
		return nil
	}
	return fmt.Errorf("printer does not log to text")
}
