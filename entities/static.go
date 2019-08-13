package entities


type StaticAnalysis struct {
	Binary BinaryAnalysis `json:"binary"`
	Code CodeAnalysis `json:"code"`
	Files FileAnalysis `json:"files"`
	Plist PListAnalysis `json:"plist"`
	Static StaticAnalysis `json:"static"`
	Virus VirusAnalysis `json:"virus"`
}
