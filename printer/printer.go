package printer

type Printer interface {
	PrintiTunesResults(appID string, country string)
	PrintPlistResults(src string, isSrc bool)
}
