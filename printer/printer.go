package printer

import "io"

type FormatMethod int

type AnalysisResult = map[string]interface{}

const (
	Store FormatMethod = iota
	PList
)

type Printer interface {
	Log(*AnalysisResult, error, FormatMethod)
	Generate(*io.Writer) error
}
