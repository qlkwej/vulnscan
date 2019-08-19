package ios

import (
	"flag"
	"fmt"
	"github.com/simplycubed/vulnscan/usecases/binary"
	"github.com/simplycubed/vulnscan/utils"
	"os"
	"os/exec"
	"path"
	"regexp"
	"runtime"
	"strings"

	"github.com/kardianos/osext"
)

// AnalysisCommand type determines the otool command flags.
type CommandType int

const (
	Libs CommandType = iota
	Header
	Symbols
)

// BinType is the programming language of the binary
type BinType int

const (
	Swift BinType = iota
	ObjC
)

// Returns the folder where the program external binary tools (jtool, class-dump) is present. By default, depending on
// the environment where the program is executing (testing/not testing) the tools will be in vulnscan/tools/tools
// (testing) or in a sibling folder of the vulnscan binary. The function also looks for a folder configured using the
// configuration file.
func getToolsFolder() string {
	if tf := utils.Configuration.ToolsFolder; tf != "" {
		return tf
	}
	var parentFolder string
	if flag.Lookup("test.v") == nil {
		parentFolder, _ = osext.ExecutableFolder()
	} else {
		parentFolder, _ = utils.FindMainFolder()
	}
	return parentFolder + string(os.PathSeparator) + "tools" + string(os.PathSeparator)
}

// Calls the otool/jtool with different arguments depending on the passed CommandType to analyze the binary
// at binPath.
func getOtoolOut(binPath string, ct CommandType) (string, error) {
	var (
		// The main command (otool/jtool)
		command string
		// The args to pass to otool/jtool. We use an array of arrays to accumulate different calls in case we have to
		// do them (jtool symbols case).
		args [][]string
	)
	// FORCE_LINUX flag is mostly for testing, although it could be used to use jtool on a mac environment
	if platform := runtime.GOOS; os.Getenv("FORCE_LINUX") == "1" || platform == "linux" {
		command = getToolsFolder() + "jtool"
		if ct == Libs {
			args = append(args, []string{"-arch", "arm", "-L", "-v", binPath})
		} else if ct == Header {
			args = append(args, []string{"-arch", "arm", "-h", "-v", binPath})
		} else if ct == Symbols {
			args = append(args, []string{"-arch", "arm", "-bind", "-v", binPath})
			args = append(args, []string{"-arch", "arm", "-lazy_bind", "-v", binPath})
		}

	} else if platform == "darwin" {
		command = "otool"
		if ct == Libs {
			args = append(args, []string{"-L", binPath})
		} else if ct == Header {
			args = append(args, []string{"-hv", binPath})
		} else if ct == Symbols {
			args = append(args, []string{"-Iv", binPath})
		}
	} else {
		return "", fmt.Errorf("platform %s not supported", platform)
	}
	var sb strings.Builder
	for _, arg := range args {
		if out, e := exec.Command(command, arg...).CombinedOutput(); e != nil {
			return string(out), e
		} else {
			sb.WriteString(string(out))
			sb.WriteString("\n")
		}
	}
	return sb.String(), nil
}

// Calls the otool/jtool with different arguments and translates the responses into analysis flags.
func otoolAnalysis(binPath string) (res map[string]interface{}, err error) {
	res = map[string]interface{}{}

	// Libs analysis
	libs, err := getOtoolOut(binPath, Libs)
	res["libs"] = strings.Split(libs, "\n")
	if err != nil {
		return res, err
	}
	var madeAnalysis []map[string]interface{}

	// Headers analysis
	pieDat, err := getOtoolOut(binPath, Header)
	if err != nil {
		return res, err
	}
	if strings.Contains(pieDat, "PIE") {
		madeAnalysis = append(madeAnalysis, map[string]interface{}{
			"issue":  "fPIE -pie flag is Found",
			"status": "secure",
			"description": "App is compiled with Position Independent Executable (PIE) flag. This enables Address " +
				"Space Layout Randomization (ASLR), a memory protectionmechanism for exploit mitigation.",
			"cvss": 0.,
			"cwe":  "",
		})
	} else {
		madeAnalysis = append(madeAnalysis, map[string]interface{}{
			"issue":  "fPIE -pie flag is not Found",
			"status": "insecure",
			"description": "App is not compiled with Position Independent Executable (PIE) flag. So Address Space " +
				"Layout Randomization (ASLR) is missing. ASLR is a memory protection mechanism for exploit mitigation.",
			"cvss": 2.,
			"cwe":  "",
		})
	}

	// Symbols analysis
	dat, err := getOtoolOut(binPath, Symbols)
	if err != nil {
		return res, err
	}
	if strings.Contains(dat, "stack_chk_guard") {
		madeAnalysis = append(madeAnalysis, map[string]interface{}{
			"issue":  "fstack-protector-all flag is Found",
			"status": "secure",
			"description": "App is compiled with Stack Smashing Protector (SSP) flag and is having protection against " +
				"Stack Overflows/Stack Smashing Attacks.",
			"cvss": 0.,
			"cwe":  "",
		})
	} else {
		madeAnalysis = append(madeAnalysis, map[string]interface{}{
			"issue":  "fstack-protector-all flag is not Found",
			"status": "insecure",
			"description": "App is not compiled with Stack Smashing Protector (SSP) flag. It is vulnerable to Stack " +
				"Overflows/Stack Smashing Attacks.",
			"cvss": 2.,
			"cwe":  "CWE-119",
		})
	}
	if strings.Contains(dat, "_objc_release") {
		madeAnalysis = append(madeAnalysis, map[string]interface{}{
			"issue":  "fobjc-arc flag is Found",
			"status": "secure",
			"description": "App is compiled with Automatic Reference Counting (ARC) flag. ARC is a compiler feature " +
				"that provides automatic memory management of Objective-C objects and is anexploit mitigation " +
				"mechanism against memory corruption vulnerabilities.",
			"cvss": 0.,
			"cwe":  "",
		})
	} else {
		madeAnalysis = append(madeAnalysis, map[string]interface{}{
			"issue":  "fobjc-arc flag is not Found",
			"status": "insecure",
			"description": "App is not compiled with Automatic Reference Counting (ARC) flag. ARC is a compiler " +
				"feature that provides automatic memory management of Objective-C objects and protects from memory " +
				"corruption vulnerabilities.",
			"cvss": 2.,
			"cwe":  "CWE-119",
		})
	}
	// Here we build a loop in order to execute multiple similar regex tests over the otool/jtool output.
	type analysis struct {
		reg  string
		bad  func(string) map[string]interface{}
		good map[string]interface{}
	}
	for _, an := range []analysis{
		{
			"_alloca|_gets|_memcpy|_printf|_scanf|_sprintf|_sscanf|_strcat|StrCat|_strcpy|" +
				"StrCpy|_strlen|StrLen|_strncat|StrNCat|_strncpy|StrNCpy|_strtok|_swprintf|_vsnprintf|" +
				"_vsprintf|_vswprintf|_wcscat|_wcscpy|_wcslen|_wcsncat|_wcsncpy|_wcstok|_wmemcpy|" +
				"_fopen|_chmod|_chown|_stat|_mktemp",
			func(s string) map[string]interface{} {
				return map[string]interface{}{
					"issue":       "Binary make use of banned API(s)",
					"status":      "insecure",
					"description": "The binary may contain the following banned API(s) " + s,
					"cvss":        6.,
					"cwe":         "CWE-676",
				}
			},
			map[string]interface{}{
				"issue":       "Binary use of banned API(s) not found",
				"status":      "secure",
				"description": "The binary has not detectable banned APIs",
				"cvss":        0.,
				"cwe":         "",
			},
		},
		{
			"kCCAlgorithmDES|kCCAlgorithm3DES|kCCAlgorithmRC2|kCCAlgorithmRC4|" +
				"kCCOptionECBMode|kCCOptionCBCMode",
			func(s string) map[string]interface{} {
				return map[string]interface{}{
					"issue":       "Binary make use of some Weak Crypto API(s)",
					"status":      "insecure",
					"description": "The binary may contain the following weak crypto API(s) " + s,
					"cvss":        6.,
					"cwe":         "CWE-676",
				}
			},
			map[string]interface{}{
				"issue":       "Binary use of banned APIs not found",
				"status":      "secure",
				"description": "The binary has not detectable banned APIs",
				"cvss":        0.,
				"cwe":         "",
			},
		},
		{
			"CCKeyDerivationPBKDF|CCCryptorCreate|CCCryptorCreateFromData|" +
				"CCCryptorRelease|CCCryptorUpdate|CCCryptorFinal|CCCryptorGetOutputLength|" +
				"CCCryptorReset|CCCryptorRef|kCCEncrypt|kCCDecrypt|kCCAlgorithmAES128|" +
				"kCCKeySizeAES128|kCCKeySizeAES192|kCCKeySizeAES256|kCCAlgorithmCAST|" +
				"SecCertificateGetTypeID|SecIdentityGetTypeID|SecKeyGetTypeID|SecPolicyGetTypeID|" +
				"SecTrustGetTypeID|SecCertificateCreateWithData|SecCertificateCreateFromData|" +
				"SecCertificateCopyData|SecCertificateAddToKeychain|SecCertificateGetData|" +
				"SecCertificateCopySubjectSummary|SecIdentityCopyCertificate|" +
				"SecIdentityCopyPrivateKey|SecPKCS12Import|SecKeyGeneratePair|SecKeyEncrypt|" +
				"SecKeyDecrypt|SecKeyRawSign|SecKeyRawVerify|SecKeyGetBlockSize|" +
				"SecPolicyCopyProperties|SecPolicyCreateBasicX509|SecPolicyCreateSSL|" +
				"SecTrustCopyCustomAnchorCertificates|SecTrustCopyExceptions|" +
				"SecTrustCopyProperties|SecTrustCopyPolicies|SecTrustCopyPublicKey|" +
				"SecTrustCreateWithCertificates|SecTrustEvaluate|SecTrustEvaluateAsync|" +
				"SecTrustGetCertificateCount|SecTrustGetCertificateAtIndex|SecTrustGetTrustResult|" +
				"SecTrustGetVerifyTime|SecTrustSetAnchorCertificates|" +
				"SecTrustSetAnchorCertificatesOnly|SecTrustSetExceptions|SecTrustSetPolicies|" +
				"SecTrustSetVerifyDate|SecCertificateRef|" +
				"SecIdentityRef|SecKeyRef|SecPolicyRef|SecTrustRef",
			func(s string) map[string]interface{} {
				return map[string]interface{}{
					"issue":       "Binary make use of the following Crypto API(s)",
					"status":      "info",
					"description": "The binary may use the following crypto API(s) " + s,
					"cvss":        0.,
					"cwe":         "",
				}
			},
			map[string]interface{}{
				"issue":       "No Crypto APIs found",
				"status":      "info",
				"description": "The binary does not seem to use crypto APIs ",
				"cvss":        0.,
				"cwe":         "",
			},
		},
		{
			"CC_MD2_Init|CC_MD2_Update|CC_MD2_Final|CC_MD2|MD2_Init|" +
				"MD2_Update|MD2_Final|CC_MD4_Init|CC_MD4_Update|CC_MD4_Final|CC_MD4|MD4_Init|" +
				"MD4_Update|MD4_Final|CC_MD5_Init|CC_MD5_Update|CC_MD5_Final|CC_MD5|MD5_Init|" +
				"MD5_Update|MD5_Final|MD5Init|MD5Update|MD5Final|CC_SHA1_Init|CC_SHA1_Update|" +
				"CC_SHA1_Final|CC_SHA1|SHA1_Init|SHA1_Update|SHA1_Final",
			func(s string) map[string]interface{} {
				return map[string]interface{}{
					"issue":       "Binary make use of the following Weak HASH API(s)",
					"status":      "insecure",
					"description": "The binary may use the following weak hash API(s) " + s,
					"cvss":        3.,
					"cwe":         "CWE-327",
				}
			},
			map[string]interface{}{
				"issue":       "Binary doesn't seem to use Weak HASH APIs",
				"status":      "secure",
				"description": "The binary may not use Weak HASH APIs",
				"cvss":        0.,
				"cwe":         "",
			},
		},
		{
			"CC_SHA224_Init|CC_SHA224_Update|CC_SHA224_Final|CC_SHA224|" +
				"SHA224_Init|SHA224_Update|SHA224_Final|CC_SHA256_Init|CC_SHA256_Update|" +
				"CC_SHA256_Final|CC_SHA256|SHA256_Init|SHA256_Update|SHA256_Final|" +
				"CC_SHA384_Init|CC_SHA384_Update|CC_SHA384_Final|CC_SHA384|SHA384_Init|" +
				"SHA384_Update|SHA384_Final|CC_SHA512_Init|CC_SHA512_Update|CC_SHA512_Final|" +
				"CC_SHA512|SHA512_Init|SHA512_Update|SHA512_Final",
			func(s string) map[string]interface{} {
				return map[string]interface{}{
					"issue":       "Binary make use of the following HASH API(s)",
					"status":      "info",
					"description": "The binary may use the following hash API(s) " + s,
					"cvss":        0.,
					"cwe":         "",
				}
			},
			map[string]interface{}{
				"issue":       "Binary doesn't seem to make use of HASH APIs",
				"status":      "info",
				"description": "The binary may not use hash APIs",
				"cvss":        0.,
				"cwe":         "",
			},
		},
		{
			"_srand|_random",
			func(s string) map[string]interface{} {
				return map[string]interface{}{
					"issue":       "Binary make use of the insecure Random Function(s)",
					"status":      "insecure",
					"description": "The binary may use the following insecure Random Function(s) " + s,
					"cvss":        3.,
					"cwe":         "CWE-338",
				}
			},
			map[string]interface{}{
				"issue":       "Binary doesn't seem to use of the insecure Random Functions",
				"status":      "secure",
				"description": "The binary doesn't seem to use insecure Random Functions ",
				"cvss":        0.,
				"cwe":         "",
			},
		},
		{
			"_NSLog",
			func(s string) map[string]interface{} {
				return map[string]interface{}{
					"issue":       "Binary make use of Logging Function",
					"status":      "info",
					"description": "The binary may use NSLog function for logging.",
					"cvss":        7.5,
					"cwe":         "CWE-532",
				}
			},
			map[string]interface{}{
				"issue":       "Binary doesn't seem to make use of Logging Function",
				"status":      "info",
				"description": "The binary doesn't seem to use NSLog function for logging.",
				"cvss":        0.,
				"cwe":         "",
			},
		},
		{
			"_malloc",
			func(s string) map[string]interface{} {
				return map[string]interface{}{
					"issue":       "Binary make use of malloc Function",
					"status":      "insecure",
					"description": "The binary may use malloc function instead of calloc.",
					"cvss":        2.,
					"cwe":         "CWE-789",
				}
			},
			map[string]interface{}{
				"issue":       "Binary doesn't seem to make use of malloc Function",
				"status":      "secure",
				"description": "The binary doesn't seem to use malloc function instead of calloc.",
				"cvss":        0.,
				"cwe":         "",
			},
		},
		{
			"_ptrace",
			func(s string) map[string]interface{} {
				return map[string]interface{}{
					"issue":  "Binary calls ptrace Function for anti-debugging.",
					"status": "warning",
					"description": "The binary may use ptrace function. It can be used to detect and prevent debuggers. " +
						"Ptrace is not a public API and Apps that use non-public APIs will be rejected from AppStore. ",
					"cvss": 0.,
					"cwe":  "",
				}
			},
			map[string]interface{}{
				"issue":  "Binary doesn't call ptrace Function for anti-debugging.",
				"status": "info",
				"description": "The binary does not seem to use ptrace function. It can be used to detect and prevent debuggers. " +
					"Ptrace is not a public API and Apps that use non-public APIs will be rejected from AppStore. ",
				"cvss": 0.,
				"cwe":  "",
			},
		},
	} {
		reg, err := regexp.Compile(an.reg)
		if err != nil {
			return res, err
		}
		if found := reg.FindAll([]byte(dat), -1); found != nil {
			var foundSet []string
			for _, f := range found {
				sf := string(f)
				for _, a := range foundSet {
					if sf == a {
						sf = ""
					}
				}
				if len(sf) > 0 {
					foundSet = append(foundSet, sf)
				}
			}
			madeAnalysis = append(madeAnalysis, an.bad(strings.Join(foundSet, ", ")))
		} else {
			madeAnalysis = append(madeAnalysis, an.good)
		}
	}
	res["anal"] = madeAnalysis
	return res, nil
}

// Calls the class_dump binaries or jtool. Currently this just detects if the binary is using web view
// TODO: extend the analysis to look for more things?
func classDump(binPath string, binType BinType) (map[string]interface{}, error) {
	var (
		command string
		args    []string
	)
	if platform := runtime.GOOS; os.Getenv("FORCE_LINUX") == "1" || platform == "linux" {
		command = getToolsFolder() + "jtool"
		args = []string{"-arch", "arm", "-d", "objc", "-v", binPath}
	} else if platform == "darwin" {
		if binType == Swift {
			command = getToolsFolder() + "class-dump-swift"
		} else {
			command = getToolsFolder() + "class-dump-z"
		}
		args = []string{binPath}
	} else {
		return map[string]interface{}{}, fmt.Errorf("platform %s not supported", platform)
	}
	exec.Command("chmod", "777", command)
	out, err := exec.Command(command, args...).CombinedOutput()
	if err != nil {
		return map[string]interface{}{}, err
	} else {
		output := string(out)
		if strings.Contains(output, "UIWebView") {
			return map[string]interface{}{
				"issue":       "Binary uses WebView Component.",
				"status":      "info",
				"description": "The binary may use WebView Component.",
				"cvss":        0.,
				"cwe":         "",
			}, nil
		} else {
			return map[string]interface{}{
				"issue":       "Binary doesn't use WebView Component.",
				"status":      "info",
				"description": "The binary may not use WebView Component.",
				"cvss":        0.,
				"cwe":         "",
			}, nil
		}
	}
}

// Detects if the binary is written in swift or in objective-c analyzing if its libs contains libswiftCore
func detectBinType(libs []string) BinType {
	for _, lib := range libs {
		if strings.Contains(lib, "libswiftCore.dylib") {
			return Swift
		}
	}
	return ObjC
}

// Performs the binary analysis. Binary analysis is composed by the analysis of the output of the macho headers, the
// otool/jtool outputs and the class dumps performed by external tools. It returns the following data:
// map[string]interface{}{
// 		"libs": 	[]string, list of libraries used by the binary,
//		"bin_res": 	[]map[string]interface, list of analysis objects from the otool/jtool/class_dump commands. Each
//				   	object is a map with a description, issue, status, cvss and cwe fields.
//		"bin_type": "Swift"|"Objective-C"
//		"macho": 	map[string]interface{} from macho analysis, with bits (32/64 bits), endianness, cpu_type and
//					sub_cpu_type fields
// }
func BinaryAnalysis(ipaPath string, isSrc bool, appName string) (map[string]interface{}, error) {
	var analysis = map[string]interface{}{}
	if e := utils.Normalize(ipaPath, isSrc, func(p string) error {
		// We can't analyze a source folder
		if isSrc {
			return fmt.Errorf("binary analysis not supported for not binary source")
		}
		appPath, err := utils.GetApp(p)
		if err != nil {
			return err
		}
		if len(appName) == 0 {
			appName = strings.Replace(path.Base(appPath), path.Ext(appPath), "", 1)
		}
		binPath := path.Join(appPath, appName)
		if _, err := os.Stat(binPath); os.IsNotExist(err) {
			return fmt.Errorf("unable to find the binary at %s", binPath)
		}
		binInfo, err := binary.GetMachoInfo(binPath)
		if err != nil {
			return err
		}
		otoolMap, err := otoolAnalysis(binPath)
		if err != nil {
			return err
		}
		binType := detectBinType(otoolMap["libs"].([]string))
		clsDump, err := classDump(binPath, binType)
		if err != nil {
			return err
		}
		analysis["libs"] = otoolMap["libs"]
		analysis["bin_res"] = append(otoolMap["anal"].([]map[string]interface{}), clsDump)
		analysis["macho"] = binInfo
		if binType == Swift {
			analysis["bin_type"] = "Swift"
		} else {
			analysis["bin_type"] = "Objective-C"
		}
		return nil
	}); e != nil {
		return analysis, e
	}
	return analysis, nil
}
