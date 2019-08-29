package utils

import (
	"io"
	"testing"
)

type (
	AnalysisCheck string

	Command struct {
		Path          string
		AppName       string
		AppId         string
		Country       string
		VirusTotalKey string
		Source        bool
		Analysis      map[AnalysisCheck]bool
		CheckDomains  bool
		Output        io.Writer
		T             *testing.T
	}
)

const (
	DoPList  AnalysisCheck = "DoPList"
	DoFiles  AnalysisCheck = "DoFiles"
	DoCode   AnalysisCheck = "DoCode"
	DoBinary AnalysisCheck = "DoAnalysis"
	DoStore  AnalysisCheck = "DoStore"
	DoVirus AnalysisCheck = "DoVirus"
)
