package output

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
)


var (
	binaryAnalysisTest = entities.BinaryAnalysis{
		BinType:   entities.ObjC,
		Libraries: []string{"a library", "some other library", "an even better library"},
		Macho: entities.MachoInfo{
			Bits:       entities.Bits64,
			Endianness: entities.LittleEndian,
			Cpu:        entities.PowerPC64,
			SubCpu:     entities.PowerPC601,
		},
		Results: []entities.BinaryAnalysisResult{
			{
				Issue:       "There is an issue",
				Description: "A very bad issue",
				Status:      entities.WarningStatus,
				Cvss:        10.8,
				CWE:          "CWE-144",
			},
		},
	}
	codeAnalysisTest = entities.CodeAnalysis{
		Codes:      []entities.CodeFinding{
			{
				CodeRule: entities.CodeRule{
					Description: "Files may contain hardcoded sensitive informations like usernames, passwords, keys etc.",
					Level:       entities.HighLevel,
					Cvss:        0,
					Cwe:         "CWE-312",
				},
				Paths:   []string{
					"/CocoaLumberjack/Extensions/DDDispatchQueueLogFormatter.m", "/GAFirstChallengeViewController.m",
					"/View Controllers/FlurryFirstChallengeViewController.m", "/View Controllers/SensitiveInformationDetailsVC.m",
					"/View Controllers/SideChannelDataLeakageDetailsVC.m", "/YapDatabase/YapDatabase.m",
					"/YapDatabase/YapDatabaseConnection.m",
				},
			},
		},
		Apis:       []entities.ApiFinding{
			{
				ApiRule: entities.ApiRule{
					Description: "Encryption API",
				},
				Paths:  []string{
					"/Third Party Classes/RNCryptor/RNCryptor.m", "/Third Party Classes/RNCryptor/RNDecryptor.m",
					"/Third Party Classes/RNCryptor/RNEncryptor.m", "/Third Party Classes/RNCryptor/RNOpenSSLDecryptor.m",
					"/Third Party Classes/RNCryptor/RNOpenSSLEncryptor.m", "/View Controllers/BrokenCryptographyDetailsVC.m",
				},
			},
		},
		Urls:       []entities.UrlFinding{
			{
				Url: "http://code.google.com",
				Paths: []string{"/CocoaLumberjack/DDTTYLogger.m", "/CocoaLumberjack/DDTTYLogger.m", "/CocoaLumberjack/DDTTYLogger.m"},
			},
		},
		Emails:     []entities.EmailFinding{
			{
				Email: "an@email.com",
				Paths: []string{
					"/Third Party Classes/ECSlidingViewController/ECPercentDrivenInteractiveTransition.m",
					"/Third Party Classes/ECSlidingViewController/ECSlidingAnimationController.m",
					"/Third Party Classes/ECSlidingViewController/ECSlidingInteractiveTransition.m",
					"/Third Party Classes/ECSlidingViewController/ECSlidingSegue.m",
					"/Third Party Classes/ECSlidingViewController/ECSlidingViewController.m",
					"/Third Party Classes/ECSlidingViewController/UIViewControllerxECSlidingViewController.m",
				},
			},
		},
	}
	filesAnalysisTest = entities.FileAnalysis{
		Files:          []string{},
		Certifications: []string{},
		Databases: []string{"/README.md", "/iVim", "/iVim/ArgumentToken.swift", "/iVim/Assets.xcassets",
			"/iVim/Assets.xcassets/AppIcon.appiconset", "/iVim/Assets.xcassets/AppIcon.appiconset/Contents.json",
		},
		PLists: []string{"/iVim/Info.plist", "/iVim/Settings.bundle/Root.plist", "/iVim/systemFonts.plist",
			"/iVim.xcodeproj/project.xcworkspace/xcshareddata/IDEWorkspaceChecks.plist",
		},
	}
	plistAnalysisTest = entities.PListAnalysis{
		Xml: "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" " +
			"\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n\t<dict>\n\t\t" +
			"<key>CFBundleDisplayName</key>\n\t\t<string></string>\n\t\t<key>CFBundleExecutable</key>\n\t\t" +
			"<string>iVim</string>\n\t\t<key>CFBundleIdentifier</key>\n\t\t<string>com.terrychou.ivim</string>\n\t\t" +
			"<key>CFBundleLocalizations</key>\n\t\t<array></array>\n\t\t<key>CFBundleName</key>\n\t\t" +
			"<string>iVim</string>\n\t\t<key>CFBundleShortVersionString</key>\n\t\t<string>1.40</string>\n\t\t" +
			"<key>CFBundleSupportedPlatforms</key>\n\t\t<array>\n\t\t\t<string>iPhoneSimulator</string>\n\t\t" +
			"</array>\n\t\t<key>CFBundleURLTypes</key>\n\t\t<array>\n\t\t\t<dict>\n\t\t\t\t" +
			"<key>CFBundleURLName</key>\n\t\t\t\t<string>com.terrychou.vim</string>\n\t\t\t\t" +
			"<key>CFBundleURLSchemes</key>\n\t\t\t\t<array>\n\t\t\t\t\t<string>ivimeditor</string>\n\t\t\t\t" +
			"</array>\n\t\t\t</dict>\n\t\t</array>\n\t\t<key>CFBundleVersion</key>\n\t\t<string>1</string>\n\t\t" +
			"<key>DTPlatformVersion</key>\n\t\t<string>12.1</string>\n\t\t<key>DTSDKName</key>\n\t\t" +
			"<string>iphonesimulator12.1</string>\n\t\t<key>MinimumOSVersion</key>\n\t\t<string>9.1</string>\n\t\t" +
			"<key>NSAppTransportSecurity</key>\n\t\t<dict>\n\t\t\t<key>NSAllowsArbitraryLoads</key><false/>\n\t\t\t" +
			"<key>NSExceptionDomains</key>\n\t\t\t<dict></dict>\n\t\t</dict>\n\t\t" +
			"<key>NSAppleMusicUsageDescription</key>\n\t\t<string></string>\n\t\t" +
			"<key>NSBluetoothPeripheralUsageDescription</key>\n\t\t<string></string>\n\t\t" +
			"<key>NSCalendarsUsageDescription</key>\n\t\t<string></string>\n\t\t<key>NSCameraUsageDescription</key>\n\t\t" +
			"<string></string>\n\t\t<key>NSContactsUsageDescription</key>\n\t\t<string></string>\n\t\t" +
			"<key>NSHealthShareUsageDescription</key>\n\t\t<string></string>\n\t\t" +
			"<key>NSHealthUpdateUsageDescription</key>\n\t\t<string></string>\n\t\t" +
			"<key>NSHomeKitUsageDescription</key>\n\t\t<string></string>\n\t\t" +
			"<key>NSLocationAlwaysUsageDescription</key>\n\t\t<string></string>\n\t\t" +
			"<key>NSLocationUsageDescription</key>\n\t\t<string></string>\n\t\t" +
			"<key>NSLocationWhenInUseUsageDescription</key>\n\t\t<string></string>\n\t\t" +
			"<key>NSMicrophoneUsageDescription</key>\n\t\t<string></string>\n\t\t" +
			"<key>NSMotionUsageDescription</key>\n\t\t<string></string>\n\t\t<key>NSPhotoLibraryUsageDescription</key>\n\t\t" +
			"<string></string>\n\t\t<key>NSRemindersUsageDescription</key>\n\t\t<string></string>\n\t\t" +
			"<key>NSVideoSubscriberAccountUsageDescription</key>\n\t\t<sting></string>\n\t</dict>\n</plist>\n",
		BinName:                  "iVim",
		Bin:                      "iVim",
		Id:                       "com.terrychou.ivim",
		Build:                    "1",
		SDK:                      "iphonesimulator12.1",
		Platform:                 "12.1",
		MinimumVersion:           "9.1",
		BundleName:               "iVim",
		BundleVersionName:        "1",
		BundleSupportedPlatforms: []string{"iPhoneSimulator"},
		BundleLocalizations:      []string{"es"},
		BundleUrlTypes:           []entities.BundleUrlType{
			{
				Name:    "com.terrychou.vim",
				Schemas: []string{"ivimeditor"},
			},
		},
		Permissions:              []entities.Permission{
			{
				Name:        "NSMicrophoneUsageDescription",
				Description: "Access microphone.",
				Reason:      "Reason",
			},
		},
		InsecureConnections:      entities.InsecureConnections{
			AllowArbitraryLoads: false,
			Domains:             []string{},
		},
	}
	storeAnalysisTest = entities.StoreAnalysis{
		Count:   1,
		Results: []entities.StoreResult{
			{
				Features:         []string{"iosUniversal"},
				IconUrl512:       "https://is3-ssl.mzstatic.com/image/thumb/Purple113/v4/8a/90/7c/8a907c33-8260-29d7-b395-53e466984979/source/512x512bb.jpg",
				IconUrl100:       "https://is3-ssl.mzstatic.com/image/thumb/Purple113/v4/8a/90/7c/8a907c33-8260-29d7-b395-53e466984979/source/100x100bb.jpg",
				IconUrl60:        "https://is3-ssl.mzstatic.com/image/thumb/Purple113/v4/8a/90/7c/8a907c33-8260-29d7-b395-53e466984979/source/60x60bb.jpg",
				DeveloperId:      48188146,
				DeveloperName:    "Edison Software Inc.",
				DeveloperUrl:     "https://apps.apple.com/us/developer/edison-software-inc/id481881468?uo=4",
				DeveloperWebsite: "http://mail.edison.tech",
				SupportedDevices: []string{"iPhone5-iPhone5", "iPadFourthGen-iPadFourthGen", "iPadFourthGen4G-iPadFourthGen4G"},
				Title:             "Email - Edison Mail",
				AppId:            "com.easilydo.mail",
				Categories:       []string{"Productivity", "Business"},
				Description:     "Description",
				Price:            0.0,
				Url:              "https://apps.apple.com/us/app/email-edison-mail/id922793622?uo=4",
				Score:            4.5,
			},
		},
	}
	virusAnalysisTest = entities.VirusAnalysis{
		HasReport: true,
		Response:  entities.VirusResponse{
			ResponseCode: 1,
			VerboseMsg:   "Scan finished, information embedded",
			Resource:     "b956666c9670cff7166d28af88a3e063",
			ScanId:       "11ff8b84c2dd786d259ace96c7a658e79a667d76db33fc3b2f1b021504d03144-1565653959",
			Sha256:       "11ff8b84c2dd786d259ace96c7a658e79a667d76db33fc3b2f1b021504d03144",
			Permalink:    "https://www.virustotal.com/file/11ff8b84c2dd786d259ace96c7a658e79a667d76db33fc3b2f1b021504d03144/analysis/1565653959/",
		},
		Report:    entities.VirusReport{
			VirusResponse: entities.VirusResponse{
				ResponseCode: 1,
				VerboseMsg:   "Scan finished, information embedded",
				Resource:     "b956666c9670cff7166d28af88a3e063",
				ScanId:       "11ff8b84c2dd786d259ace96c7a658e79a667d76db33fc3b2f1b021504d03144-1565653959",
				Sha256:       "11ff8b84c2dd786d259ace96c7a658e79a667d76db33fc3b2f1b021504d03144",
				Permalink:    "https://www.virustotal.com/file/11ff8b84c2dd786d259ace96c7a658e79a667d76db33fc3b2f1b021504d03144/analysis/1565653959/",
			},
			Md5:           "b956666c9670cff7166d28af88a3e063",
			Sha1:          "01d4f5b3a7d81a02c8be039124c08a0e389f3eb3",
			ScanDate:      "2019-08-12 23:52:39",
			Positives:     0,
			Total:         54,
			Scans: map[string]entities.VirusScan{
				"ALYac": {
					false,
					"1.1.1.5",
					"",
					"20190812",

				},
				"Ad-Aware": {
					false,
					"3.0.5.370",
					"",
					"20190813",
				},
			},
		},
	}
	staticAnalysisTest = entities.StaticAnalysis{
		HasBinary: true,
		HasCode:   true,
		HasFiles:  true,
		HasPlist:  true,
		HasVirus:  true,
		HasStore:  true,
		Binary:    binaryAnalysisTest,
		Code:      codeAnalysisTest,
		Files:     filesAnalysisTest,
		Plist:     plistAnalysisTest,
		Virus:     virusAnalysisTest,
		Store:     storeAnalysisTest,
	}
)

// This test just tests that the Pretty console addapter doesn't throw any error and it doesn't panic. It allows to
// see a complete result too, so we can make any change on the styling.
func TestPrettyConsoleAdapter(t *testing.T) {
	var (
		buffer bytes.Buffer
		command = utils.Command{
			Output: &buffer,
		}
	)
	assert.NoError(t, PrettyConsoleAdapter(command, &staticAnalysisTest))
	t.Log(buffer.String())
}
