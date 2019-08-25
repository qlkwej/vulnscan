package utils



type (
	AnalysisCheck string

	Command struct {
		Path    	string
		AppName 	string
		AppId 		string
		Country 	string
		Source 		bool
		Analysis 	map[AnalysisCheck]bool
	}
)

const (
	DoPList AnalysisCheck = "DoPList"
	DoFiles AnalysisCheck = "DoFiles"
	DoCode AnalysisCheck = "DoCode"
	DoBinary AnalysisCheck = "DoAnalysis"
	DoStore AnalysisCheck = "DoStore"
)
