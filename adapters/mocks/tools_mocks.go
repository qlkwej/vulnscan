package mocks

import (
	"fmt"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
	"os"
)

func LibsAdapter(command utils.Command, entity *entities.BinaryAnalysis) error {
	if _, err := os.Stat(command.Path); os.IsNotExist(err) {
		return fmt.Errorf("command.path doesn't exists")
	}
	entity.Libraries = []string{
		"/this/is/a/library",
		"/path/to/the/holly/grial",
		"/etc/libs/indiana/jones",
		"/so/close/and/so/far/at_the_same_time.dylib",
	}
	return nil
}

func HeadersAdapter(command utils.Command, entity *entities.BinaryAnalysis) error {
	if _, err := os.Stat(command.Path); os.IsNotExist(err) {
		return fmt.Errorf("command.path doesn't exists")
	}
	entity.Results = append(entity.Results, entities.BinaryAnalysisResult{
		Issue:  "fPIE -pie flag is Found",
		Status: "secure",
		Description: "App is compiled with Position Independent Executable (PIE) flag. This enables Address " +
			"Space Layout Randomization (ASLR), a memory protectionmechanism for exploit mitigation.",
		Cvss: 0.,
		CWE:  "",
	})
	return nil
}

func SymbolsAdapter(command utils.Command, entity *entities.BinaryAnalysis) error {
	if _, err := os.Stat(command.Path); os.IsNotExist(err) {
		return fmt.Errorf("command.path doesn't exists")
	}
	entity.Results = append(entity.Results, []entities.BinaryAnalysisResult{
		{
			Issue:  "fstack-protector-all flag is Found",
			Status: "secure",
			Description: "App is compiled with Stack Smashing Protector (SSP) flag and is having protection against " +
				"Stack Overflows/Stack Smashing Attacks.",
			Cvss: 0.,
			CWE:  "",
		},
		{
			Issue:  "fobjc-arc flag is Found",
			Status: "secure",
			Description: "App is compiled with Automatic Reference Counting (ARC) flag. ARC is a compiler feature " +
				"that provides automatic memory management of Objective-C objects and is anexploit mitigation " +
				"mechanism against memory corruption vulnerabilities.",
			Cvss: 0.,
			CWE:  "",
		},
		{
			Issue:  "fobjc-arc flag is not Found",
			Status: "insecure",
			Description: "App is not compiled with Automatic Reference Counting (ARC) flag. ARC is a compiler " +
				"feature that provides automatic memory management of Objective-C objects and protects from memory " +
				"corruption vulnerabilities.",
			Cvss: 2.,
			CWE:  "CWE-119",
		},
		{
			Issue:       "Binary use of banned API(s) not found",
			Status:      "secure",
			Description: "The binary has not detectable banned APIs",
			Cvss:        0.,
			CWE:         "",
		},
		{
			Issue:       "Binary use of banned APIs not found",
			Status:      "secure",
			Description: "The binary has not detectable banned APIs",
			Cvss:        0.,
			CWE:         "",
		},
		{
			Issue:       "No Crypto APIs found",
			Status:      "info",
			Description: "The binary does not seem to use crypto APIs ",
			Cvss:        0.,
			CWE:         "",
		},
		{
			Issue:       "Binary doesn't seem to use Weak HASH APIs",
			Status:      "secure",
			Description: "The binary may not use Weak HASH APIs",
			Cvss:        0.,
			CWE:         "",
		},
		{
			Issue:       "Binary doesn't seem to make use of HASH APIs",
			Status:      "info",
			Description: "The binary may not use hash APIs",
			Cvss:        0.,
			CWE:         "",
		},
		{
			Issue:       "Binary doesn't seem to use of the insecure Random Functions",
			Status:      "secure",
			Description: "The binary doesn't seem to use insecure Random Functions ",
			Cvss:        0.,
			CWE:         "",
		},
		{
			Issue:       "Binary make use of Logging Function",
			Status:      "info",
			Description: "The binary may use NSLog function for logging.",
			Cvss:        7.5,
			CWE:         "CWE-532",
		},
		{
			Issue:       "Binary make use of malloc Function",
			Status:      "insecure",
			Description: "The binary may use malloc function instead of calloc.",
			Cvss:        2.,
			CWE:         "CWE-789",
		},
		{
			Issue:  "Binary calls ptrace Function for anti-debugging.",
			Status: "warning",
			Description: "The binary may use ptrace function. It can be used to detect and prevent debuggers. " +
				"Ptrace is not a public API and Apps that use non-public APIs will be rejected from AppStore. ",
			Cvss: 0.,
			CWE:  "",
		},
	}...)
	return nil
}

func MockClassDumpAdapter(command utils.Command, entity *entities.BinaryAnalysis) error {
	if _, err := os.Stat(command.Path); os.IsNotExist(err) {
		return fmt.Errorf("command.path doesn't exists")
	}
	entity.Results = append(entity.Results, entities.BinaryAnalysisResult{
		Issue:       "Binary uses WebView Component.",
		Description: "The binary may use WebView Component.",
		Status:      "info",
		Cvss:        0.,
		CWE:         "",
	})
	return nil
}
