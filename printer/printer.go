package printer

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/simplycubed/vulnscan/ios"
	"github.com/sirupsen/logrus"
)

type Output int
type Kind int

const (
	Log Kind = 0
	Json Kind = 1
	StdOut Output = 0
	Text Output = 1
	ColoredText Output = 2
)

type Printer struct {
	log *logrus.Logger
	kind Kind
	output Output
}

func Get(kind Kind, output Output) Printer {
	var (
		out io.Writer
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
	if output ==StdOut {
		out = os.Stdout
	} else {
		out = new(TextWriter)
	}

	return Printer{
		&logrus.Logger{
			Out: out,
			Formatter: formatter,
			Hooks: make(logrus.LevelHooks),
			Level: logrus.DebugLevel,
		},
		kind,
		output,
	}
}

func (p Printer) PrintiTunesResults(appID string, country string) {
	resp := ios.Search(appID, country)
	entry := p.log.WithFields(logrus.Fields{"analysis": "iTunes"})
	entry.WithFields(logrus.Fields{"count": resp.ResultCount}).Info("Total results")
	for i, r := range resp.Results {
		entry.WithFields(logrus.Fields{"title": r.Title, "url": r.ItunesURL}).
			Info(fmt.Sprintf("Result %d", i + 1))
	}
}



func (p Printer) PrintPlistResults(src string, isSrc bool) {
	resp, err := ios.PListAnalysis(src, isSrc)
	entry := p.log.WithFields(logrus.Fields{"analysis": "plist"})
	if err != nil {
		p.log.WithFields(logrus.Fields{"analysis": "plist"}).WithFields(logrus.Fields{"message": err}).Info("Error")
	}
	generalMap, bundleMap := map[string]interface{}{}, map[string]interface{}{}
	for k, v := range resp {
		if k == "permissions"{
			for i, m := range v.([]map[string]interface{}) {
				entry.WithFields(m).Info(fmt.Sprintf("Permission %d", i + 1))
			}
		} else if k == "insecure_connections" {
			connMap := v.(map[string]interface{})
			entry.WithFields(logrus.Fields{"allow_arbitrary_loads": connMap["allow_arbitrary_loads"],
				"domains": strings.Join(connMap["domains"].([]string), ", ")}).Info("Insecure connections")
		} else if strings.HasPrefix(k, "bundle") {
			bundleMap[k] = v
		} else {
			generalMap[k] = v
		}
	}
	entry.WithFields(generalMap).Info("General information")
	entry.WithFields(bundleMap).Info("Bundle information")
}

func (p Printer) ToString() (string, error) {
	if p.output != Text {
		return "", fmt.Errorf("printer does not log to text")
	}
	var ordErr error
	var a [2]string
	var t [2]time.Time
	layout := time.RFC3339  // Taken from https://github.com/sirupsen/logrus/blob/master/formatter.go
	if writer, ok := p.log.Out.(*TextWriter); ok {
		sort.Slice(writer.inner, func(i, j int) bool {
			if p.kind == Json {
				for i, b := range [2][]byte { []byte(writer.inner[i]), []byte(writer.inner[j]) } {
					var m map[string]string; ordErr = json.Unmarshal(b, &m)
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
				for i, s := range []string{ writer.inner[i], writer.inner[j] } {
					ss := strings.Split(s, " ")
					for _, w := range ss {
						if strings.HasPrefix(w, "time") {
							t[i], ordErr = time.Parse(layout, strings.Split(w, "=")[1])
						} else if strings.HasPrefix(w,"analysis") {
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
			return "", ordErr
		}
		var b strings.Builder
		for _, s := range writer.inner {
			b.WriteString(s)
			b.WriteString("\n")
		}
		return b.String(), nil
	}
	return "", fmt.Errorf("printer does not log to text")
}



