package printer

import "io"

// FormatMethod identifies if the results will be in Log for JSON format
type FormatMethod int

// AnalysisResult is the results from the security scan
type AnalysisResult = map[string]interface{}

const (
	// Store is the apple store lookup
	Store FormatMethod = iota
	// PList is the plist scan
	PList
	ListFiles
	VirusScan
)

// Printer is the interface used to decouple scans from printing
type Printer interface {
	Log(AnalysisResult, error, FormatMethod)
	Generate(io.Writer) error
}
