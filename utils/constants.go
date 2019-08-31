package utils

// We put here the urls because they must be imported from the downloader test and from main and we need to avoid:
// 		a. Duplicate them, giving room to mistakes
//		b. Circular imports
const (
	JtoolUrl = "https://github.com/simplycubed/vulnscan-dependencies/releases/download/0.0.1-beta/jtool"
	ClassDumpZUrl = "https://github.com/simplycubed/vulnscan-dependencies/releases/download/0.0.1-beta/class-dump-z"
	ClassDumpSwiftUrl = "https://github.com/simplycubed/vulnscan-dependencies/releases/download/0.0.1-beta/class-dump-swift"
)
