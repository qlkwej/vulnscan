package utils



type (
	AnalysisCheck string

	Command struct {
		Path    string
		AppName string
		Source bool
		Analysis map[AnalysisCheck]bool
	}
)

const (
	DoPList AnalysisCheck = "DoPList"
	DoFiles AnalysisCheck = "DoFiles"
	DoCode AnalysisCheck = "DoCode"
	DoBinary AnalysisCheck = "DoAnalysis"
	DoStore AnalysisCheck = "DoStore"
)
