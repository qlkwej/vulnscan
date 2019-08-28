package utils

import "io"

type (
	AnalysisCheck string

	Command struct {
		Path    		string
		AppName 		string
		AppId 			string
		Country 		string
		VirusTotalKey	string
		Source 			bool
		Analysis 		map[AnalysisCheck]bool
		Output 			io.Writer
	}
)

const (
	DoPList AnalysisCheck = "DoPList"
	DoFiles AnalysisCheck = "DoFiles"
	DoCode AnalysisCheck = "DoCode"
	DoBinary AnalysisCheck = "DoAnalysis"
	DoStore AnalysisCheck = "DoStore"
)
