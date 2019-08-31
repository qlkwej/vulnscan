package tools

import (
	"fmt"
	"github.com/simplycubed/vulnscan/entities"
	"os"
	"os/exec"
	"regexp"
	"strings"
)



func performJtoolAnalysis(command entities.Command, args [][]string) (out string, err error) {
	com := command.Tools + "jtool"
	if _, err := os.Stat(com); os.IsNotExist(err) {
		return out, fmt.Errorf("jtool not found on %s, probably it's not installed", command)
	}
	var sb strings.Builder
	for _, arg := range args {
		if out, e := exec.Command(com, arg...).CombinedOutput(); e != nil {
			return string(out), e
		} else {
			sb.WriteString(string(out))
			sb.WriteString("\n")
		}
	}
	return sb.String(), nil
}

func headerExtractor(out string, entity *entities.BinaryAnalysis) error {
	if strings.Contains(out, "PIE") {
		entity.Results = append(entity.Results, entities.BinaryAnalysisResult{
			Issue:  "fPIE -pie flag is Found",
			Status: "secure",
			Description: "App is compiled with Position Independent Executable (PIE) flag. This enables Address " +
				"Space Layout Randomization (ASLR), a memory protectionmechanism for exploit mitigation.",
			Cvss: 0.,
			CWE:  "",
		})
		return nil
	} else {
		entity.Results = append(entity.Results, entities.BinaryAnalysisResult{
			Issue:  "fPIE -pie flag is not Found",
			Status: "insecure",
			Description: "App is not compiled with Position Independent Executable (PIE) flag. So Address Space " +
				"Layout Randomization (ASLR) is missing. ASLR is a memory protection mechanism for exploit mitigation.",
			Cvss: 2.,
			CWE:  "",
		})
	}
	return nil
}

func symbolExtractor(out string, entity *entities.BinaryAnalysis) error {
	if strings.Contains(out, "stack_chk_guard") {
		entity.Results = append(entity.Results, entities.BinaryAnalysisResult{
			Issue:  "fstack-protector-all flag is Found",
			Status: "secure",
			Description: "App is compiled with Stack Smashing Protector (SSP) flag and is having protection against " +
				"Stack Overflows/Stack Smashing Attacks.",
			Cvss: 0.,
			CWE:  "",
		})
	} else {
		entity.Results = append(entity.Results, entities.BinaryAnalysisResult{
			Issue:  "fstack-protector-all flag is not Found",
			Status: "insecure",
			Description: "App is not compiled with Stack Smashing Protector (SSP) flag. It is vulnerable to Stack " +
				"Overflows/Stack Smashing Attacks.",
			Cvss: 2.,
			CWE:  "CWE-119",
		})
	}
	if strings.Contains(out, "_objc_release") {
		entity.Results = append(entity.Results, entities.BinaryAnalysisResult{
			Issue:  "fobjc-arc flag is Found",
			Status: "secure",
			Description: "App is compiled with Automatic Reference Counting (ARC) flag. ARC is a compiler feature " +
				"that provides automatic memory management of Objective-C objects and is anexploit mitigation " +
				"mechanism against memory corruption vulnerabilities.",
			Cvss: 0.,
			CWE:  "",
		})
	} else {
		entity.Results = append(entity.Results, entities.BinaryAnalysisResult{
			Issue:  "fobjc-arc flag is not Found",
			Status: "insecure",
			Description: "App is not compiled with Automatic Reference Counting (ARC) flag. ARC is a compiler " +
				"feature that provides automatic memory management of Objective-C objects and protects from memory " +
				"corruption vulnerabilities.",
			Cvss: 2.,
			CWE:  "CWE-119",
		})
	}
	// Here we build a loop in order to execute multiple similar regex tests over the otool/jtool output.
	type analysis struct {
		reg  string
		bad  func(string) entities.BinaryAnalysisResult
		good entities.BinaryAnalysisResult
	}
	for _, an := range []analysis{
		{
			"_alloca|_gets|_memcpy|_printf|_scanf|_sprintf|_sscanf|_strcat|StrCat|_strcpy|" +
				"StrCpy|_strlen|StrLen|_strncat|StrNCat|_strncpy|StrNCpy|_strtok|_swprintf|_vsnprintf|" +
				"_vsprintf|_vswprintf|_wcscat|_wcscpy|_wcslen|_wcsncat|_wcsncpy|_wcstok|_wmemcpy|" +
				"_fopen|_chmod|_chown|_stat|_mktemp",
			func(s string) entities.BinaryAnalysisResult {
				return entities.BinaryAnalysisResult{
					Issue:       "Binary make use of banned API(s)",
					Status:      "insecure",
					Description: "The binary may contain the following banned API(s) " + s,
					Cvss:        6.,
					CWE:         "CWE-676",
				}
			},
			entities.BinaryAnalysisResult{
				Issue:       "Binary use of banned API(s) not found",
				Status:      "secure",
				Description: "The binary has not detectable banned APIs",
				Cvss:        0.,
				CWE:         "",
			},
		},
		{
			"kCCAlgorithmDES|kCCAlgorithm3DES|kCCAlgorithmRC2|kCCAlgorithmRC4|" +
				"kCCOptionECBMode|kCCOptionCBCMode",
			func(s string) entities.BinaryAnalysisResult {
				return entities.BinaryAnalysisResult{
					Issue:       "Binary make use of some Weak Crypto API(s)",
					Status:      "insecure",
					Description: "The binary may contain the following weak crypto API(s) " + s,
					Cvss:        6.,
					CWE:         "CWE-676",
				}
			},
			entities.BinaryAnalysisResult{
				Issue:       "Binary use of banned APIs not found",
				Status:      "secure",
				Description: "The binary has not detectable banned APIs",
				Cvss:        0.,
				CWE:         "",
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
			func(s string) entities.BinaryAnalysisResult {
				return entities.BinaryAnalysisResult{
					Issue:       "Binary make use of the following Crypto API(s)",
					Status:      "info",
					Description: "The binary may use the following crypto API(s) " + s,
					Cvss:        0.,
					CWE:         "",
				}
			},
			entities.BinaryAnalysisResult{
				Issue:       "No Crypto APIs found",
				Status:      "info",
				Description: "The binary does not seem to use crypto APIs ",
				Cvss:        0.,
				CWE:         "",
			},
		},
		{
			"CC_MD2_Init|CC_MD2_Update|CC_MD2_Final|CC_MD2|MD2_Init|" +
				"MD2_Update|MD2_Final|CC_MD4_Init|CC_MD4_Update|CC_MD4_Final|CC_MD4|MD4_Init|" +
				"MD4_Update|MD4_Final|CC_MD5_Init|CC_MD5_Update|CC_MD5_Final|CC_MD5|MD5_Init|" +
				"MD5_Update|MD5_Final|MD5Init|MD5Update|MD5Final|CC_SHA1_Init|CC_SHA1_Update|" +
				"CC_SHA1_Final|CC_SHA1|SHA1_Init|SHA1_Update|SHA1_Final",
			func(s string) entities.BinaryAnalysisResult {
				return entities.BinaryAnalysisResult{
					Issue:       "Binary make use of the following Weak HASH API(s)",
					Status:      "insecure",
					Description: "The binary may use the following weak hash API(s) " + s,
					Cvss:        3.,
					CWE:         "CWE-327",
				}
			},
			entities.BinaryAnalysisResult{
				Issue:       "Binary doesn't seem to use Weak HASH APIs",
				Status:      "secure",
				Description: "The binary may not use Weak HASH APIs",
				Cvss:        0.,
				CWE:         "",
			},
		},
		{
			"CC_SHA224_Init|CC_SHA224_Update|CC_SHA224_Final|CC_SHA224|" +
				"SHA224_Init|SHA224_Update|SHA224_Final|CC_SHA256_Init|CC_SHA256_Update|" +
				"CC_SHA256_Final|CC_SHA256|SHA256_Init|SHA256_Update|SHA256_Final|" +
				"CC_SHA384_Init|CC_SHA384_Update|CC_SHA384_Final|CC_SHA384|SHA384_Init|" +
				"SHA384_Update|SHA384_Final|CC_SHA512_Init|CC_SHA512_Update|CC_SHA512_Final|" +
				"CC_SHA512|SHA512_Init|SHA512_Update|SHA512_Final",
			func(s string) entities.BinaryAnalysisResult {
				return entities.BinaryAnalysisResult{
					Issue:       "Binary make use of the following HASH API(s)",
					Status:      "info",
					Description: "The binary may use the following hash API(s) " + s,
					Cvss:        0.,
					CWE:         "",
				}
			},
			entities.BinaryAnalysisResult{
				Issue:       "Binary doesn't seem to make use of HASH APIs",
				Status:      "info",
				Description: "The binary may not use hash APIs",
				Cvss:        0.,
				CWE:         "",
			},
		},
		{
			"_srand|_random",
			func(s string) entities.BinaryAnalysisResult {
				return entities.BinaryAnalysisResult{
					Issue:       "Binary make use of the insecure Random Function(s)",
					Status:      "insecure",
					Description: "The binary may use the following insecure Random Function(s) " + s,
					Cvss:        3.,
					CWE:         "CWE-338",
				}
			},
			entities.BinaryAnalysisResult{
				Issue:       "Binary doesn't seem to use of the insecure Random Functions",
				Status:      "secure",
				Description: "The binary doesn't seem to use insecure Random Functions ",
				Cvss:        0.,
				CWE:         "",
			},
		},
		{
			"_NSLog",
			func(s string) entities.BinaryAnalysisResult {
				return entities.BinaryAnalysisResult{
					Issue:       "Binary make use of Logging Function",
					Status:      "info",
					Description: "The binary may use NSLog function for logging.",
					Cvss:        7.5,
					CWE:         "CWE-532",
				}
			},
			entities.BinaryAnalysisResult{
				Issue:       "Binary doesn't seem to make use of Logging Function",
				Status:      "info",
				Description: "The binary doesn't seem to use NSLog function for logging.",
				Cvss:        0.,
				CWE:         "",
			},
		},
		{
			"_malloc",
			func(s string) entities.BinaryAnalysisResult {
				return entities.BinaryAnalysisResult{
					Issue:       "Binary make use of malloc Function",
					Status:      "insecure",
					Description: "The binary may use malloc function instead of calloc.",
					Cvss:        2.,
					CWE:         "CWE-789",
				}
			},
			entities.BinaryAnalysisResult{
				Issue:       "Binary doesn't seem to make use of malloc Function",
				Status:      "secure",
				Description: "The binary doesn't seem to use malloc function instead of calloc.",
				Cvss:        0.,
				CWE:         "",
			},
		},
		{
			"_ptrace",
			func(s string) entities.BinaryAnalysisResult {
				return entities.BinaryAnalysisResult{
					Issue:  "Binary calls ptrace Function for anti-debugging.",
					Status: "warning",
					Description: "The binary may use ptrace function. It can be used to detect and prevent debuggers. " +
						"Ptrace is not a public API and Apps that use non-public APIs will be rejected from AppStore. ",
					Cvss: 0.,
					CWE:  "",
				}
			},
			entities.BinaryAnalysisResult{
				Issue:  "Binary doesn't call ptrace Function for anti-debugging.",
				Status: "info",
				Description: "The binary does not seem to use ptrace function. It can be used to detect and prevent debuggers. " +
					"Ptrace is not a public API and Apps that use non-public APIs will be rejected from AppStore. ",
				Cvss: 0.,
				CWE:  "",
			},
		},
	} {
		reg, err := regexp.Compile(an.reg)
		if err != nil {
			return err
		}
		if found := reg.FindAll([]byte(out), -1); found != nil {
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
			entity.Results = append(entity.Results, an.bad(strings.Join(foundSet, ", ")))
		} else {
			entity.Results = append(entity.Results, an.good)
		}
	}
	return nil
}

func classDumpExtractor(out string, entity *entities.BinaryAnalysis) error {
	if strings.Contains(out, "UIWebView") {
		entity.Results = append(entity.Results, entities.BinaryAnalysisResult{
			Issue:       "Binary uses WebView Component.",
			Description: "The binary may use WebView Component.",
			Status:      "info",
			Cvss:        0.,
			CWE:         "",
		})
	} else {
		entity.Results = append(entity.Results, entities.BinaryAnalysisResult{
			Issue:       "Binary doesn't use WebView Component.",
			Description: "The binary may not use WebView Component.",
			Status:      "info",
			Cvss:        0.,
			CWE:         "",
		})
	}
	return nil
}
