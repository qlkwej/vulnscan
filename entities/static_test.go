package entities

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	staticAnalysisTestMap = map[string]interface{}{
		"binary": map[string]interface{}{
			"libraries": []string{"a library", "some other library", "an even better library"},
			"macho":     machoInfoTestMap,
			"results": []map[string]interface{}{
				binaryAnalysisResultMap,
			},
			"bin_type": "Swift",
		},
		"code": map[string]interface{}{
			"codes": []map[string]interface{}{
				{
					"description": "Files may contain hardcoded sensitive informations like usernames, passwords, keys etc.",
					"cvss":        7.4,
					"cwe":         "CWE-312",
					"level":       "High",
					"paths": []string{
						"/CocoaLumberjack/Extensions/DDDispatchQueueLogFormatter.m", "/GAFirstChallengeViewController.m",
						"/View Controllers/FlurryFirstChallengeViewController.m", "/View Controllers/SensitiveInformationDetailsVC.m",
						"/View Controllers/SideChannelDataLeakageDetailsVC.m", "/YapDatabase/YapDatabase.m",
						"/YapDatabase/YapDatabaseConnection.m",
					},
				},
				{
					"description": "IP Address disclosure",
					"cvss":        4.3,
					"cwe":         "CWE-200",
					"level":       "Info",
					"paths":       []string{"/YapDatabase/YapDatabase.m"},
				},
			},
			"apis": []map[string]interface{}{
				{
					"description": "Encryption API",
					"paths": []string{
						"/Third Party Classes/RNCryptor/RNCryptor.m", "/Third Party Classes/RNCryptor/RNDecryptor.m",
						"/Third Party Classes/RNCryptor/RNEncryptor.m", "/Third Party Classes/RNCryptor/RNOpenSSLDecryptor.m",
						"/Third Party Classes/RNCryptor/RNOpenSSLEncryptor.m", "/View Controllers/BrokenCryptographyDetailsVC.m",
					},
				},
			},
			"urls": []map[string]interface{}{
				{
					"url":   "http://code.google.com",
					"paths": []string{"/YapDatabase/Utilities/YapMurmurHash.m", "/YapDatabase/Utilities/YapMurmurHash.m", "/YapDatabase/Utilities/YapMurmurHash.m"},
				},
				{
					"url":   "http://en.wikipedia.org",
					"paths": []string{"/CocoaLumberjack/DDTTYLogger.m", "/CocoaLumberjack/DDTTYLogger.m", "/CocoaLumberjack/DDTTYLogger.m"},
				},
				{
					"url": "http://enriquez.me",
					"paths": []string{
						"/Third Party Classes/ECSlidingViewController/ECPercentDrivenInteractiveTransition.m",
						"/Third Party Classes/ECSlidingViewController/ECSlidingAnimationController.m",
						"/Third Party Classes/ECSlidingViewController/ECSlidingInteractiveTransition.m",
						"/Third Party Classes/ECSlidingViewController/ECSlidingSegue.m",
						"/Third Party Classes/ECSlidingViewController/ECSlidingViewController.m",
						"/Third Party Classes/ECSlidingViewController/UIViewControllerxECSlidingViewController.m",
					},
				},
			},
			"emails": []map[string]interface{}{
				{
					"email": "bar@example.com",
					"paths": []string{"/View Controllers/SolutionsViewController.m"},
				},
				{
					"email": "damien.bergamini@free.fr",
					"paths": []string{"/Third Party Classes/RNCryptor/RNCryptor.m"},
				},
				{
					"email": "foo@example.com",
					"paths": []string{"/View Controllers/SolutionsViewController.m"},
				},
			},
			"bad_domains": []string{"dangeroussitetovisit.com"},
		},
		"files": map[string]interface{}{
			"certifications": []string{},
			"databases":      []string{},
			"files": []string{"/README.md", "/iVim", "/iVim/ArgumentToken.swift", "/iVim/Assets.xcassets",
				"/iVim/Assets.xcassets/AppIcon.appiconset", "/iVim/Assets.xcassets/AppIcon.appiconset/Contents.json",
			},
			"plists": []string{"/iVim/Info.plist", "/iVim/Settings.bundle/Root.plist", "/iVim/systemFonts.plist",
				"/iVim.xcodeproj/project.xcworkspace/xcshareddata/IDEWorkspaceChecks.plist",
			},
		},
		"plist": map[string]interface{}{
			"xml": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" " +
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
				"<key>NSVideoSubscriberAccountUsageDescription</key>\n\t\t<string></string>\n\t</dict>\n</plist>\n",
			"bin":                        "iVim",
			"bin_name":                   "iVim",
			"id":                         "com.terrychou.ivim",
			"build":                      "1",
			"sdk":                        "iphonesimulator12.1",
			"platform":                   "12.1",
			"minimum_version":            "9.1",
			"bundle_name":                "iVim",
			"bundle_version_name":        "1",
			"bundle_supported_platforms": []string{"iPhoneSimulator"},
			"bundle_localizations":       []string{"es"},
			"bundle_url_types": []map[string]interface{}{
				{"name": "com.terrychou.vim", "schemas": []string{"ivimeditor"}},
			},
			"insecure_connections": map[string]interface{}{
				"allow_arbitrary_loads": false,
				"domains":               []string{},
			},
			"permissions": []map[string]interface{}{
				{
					"name":        "NSMicrophoneUsageDescription",
					"description": "Access microphone.",
					"reason":      "Reason",
				},
			},
		},
		"virus": map[string]interface{}{
			"md5":           "b956666c9670cff7166d28af88a3e063",
			"permalink":     "https://www.virustotal.com/file/11ff8b84c2dd786d259ace96c7a658e79a667d76db33fc3b2f1b021504d03144/analysis/1565653959/",
			"resource":      "b956666c9670cff7166d28af88a3e063",
			"response_code": 1,
			"scan_date":     "2019-08-12 23:52:39",
			"scan_id":       "11ff8b84c2dd786d259ace96c7a658e79a667d76db33fc3b2f1b021504d03144-1565653959",
			"sha1":          "01d4f5b3a7d81a02c8be039124c08a0e389f3eb3",
			"sha256":        "11ff8b84c2dd786d259ace96c7a658e79a667d76db33fc3b2f1b021504d03144",
			"total":         54,
			"positives":     0,
			"verbose_msg":   "Scan finished, information embedded",
			"scans": map[string]interface{}{
				"ALYac": map[string]interface{}{
					"detected": false,
					"result":   "",
					"update":   "20190812",
					"version":  "1.1.1.5",
				},
				"Ad-Aware": map[string]interface{}{
					"detected": false,
					"result":   "",
					"update":   "20190813",
					"version":  "3.0.5.370",
				},
			},
		},
		"lookup": map[string]interface{}{
			"count": 1,
			"results": []map[string]interface{}{
				{
					"features":          []string{"iosUniversal"},
					"icon_url_512":      "https://is3-ssl.mzstatic.com/image/thumb/Purple113/v4/8a/90/7c/8a907c33-8260-29d7-b395-53e466984979/source/512x512bb.jpg",
					"icon_url_100":      "https://is3-ssl.mzstatic.com/image/thumb/Purple113/v4/8a/90/7c/8a907c33-8260-29d7-b395-53e466984979/source/100x100bb.jpg",
					"icon_url_60":       "https://is3-ssl.mzstatic.com/image/thumb/Purple113/v4/8a/90/7c/8a907c33-8260-29d7-b395-53e466984979/source/60x60bb.jpg",
					"developer_id":      48188146,
					"developer_name":    "Edison Software Inc.",
					"developer_url":     "https://apps.apple.com/us/developer/edison-software-inc/id481881468?uo=4",
					"developer_website": "http://mail.edison.tech",
					"supported_devices": []string{"iPhone5-iPhone5", "iPadFourthGen-iPadFourthGen", "iPadFourthGen4G-iPadFourthGen4G"},
					"title":             "Email - Edison Mail",
					"app_id":            "com.easilydo.mail",
					"categories":        []string{"Productivity", "Business"},
					"description":       "Description",
					"price":             0.0,
					"url":               "https://apps.apple.com/us/app/email-edison-mail/id922793622?uo=4",
					"score":             4.5,
				},
			},
		},
	}

	wrongStaticAnalysisTestMap = map[string]interface{}{
		"binary": map[string]interface{}{
			"libraries": []string{},
			"macho":     wrongMachoInfoTestMap,
			"results": []map[string]interface{}{
				wrongBinaryAnalysisResultMap,
			},
			"bin_type": "Swift",
		},
		"code": map[string]interface{}{
			"codes": []map[string]interface{}{
				{
					"description": "Encryption API",
					"paths": []string{
						"/Third Party Classes/RNCryptor/RNCryptor.m", "/Third Party Classes/RNCryptor/RNDecryptor.m",
						"/Third Party Classes/RNCryptor/RNEncryptor.m", "/Third Party Classes/RNCryptor/RNOpenSSLDecryptor.m",
						"/Third Party Classes/RNCryptor/RNOpenSSLEncryptor.m", "/View Controllers/BrokenCryptographyDetailsVC.m",
					},
				},
			},
			"apis": []map[string]interface{}{
				{
					"description": "Files may contain hardcoded sensitive informations like usernames, passwords, keys etc.",
					"cvss":        7.4,
					"cws":         "CWE-312",
					"level":       "High",
					"paths": []string{
						"/CocoaLumberjack/Extensions/DDDispatchQueueLogFormatter.m", "/GAFirstChallengeViewController.m",
						"/View Controllers/FlurryFirstChallengeViewController.m", "/View Controllers/SensitiveInformationDetailsVC.m",
						"/View Controllers/SideChannelDataLeakageDetailsVC.m", "/YapDatabase/YapDatabase.m",
						"/YapDatabase/YapDatabaseConnection.m",
					},
				},
			},
			"urls": []map[string]interface{}{
				{
					"email": "bar@example.com",
					"paths": []string{"/View Controllers/SolutionsViewController.m"},
				},
				{
					"email": "damien.bergamini@free.fr",
					"paths": []string{"/Third Party Classes/RNCryptor/RNCryptor.m"},
				},
				{
					"email": "foo@example.com",
					"paths": []string{"/View Controllers/SolutionsViewController.m"},
				},
			},
			"emails": []map[string]interface{}{
				{
					"url":   "http://code.google.com",
					"paths": []string{"/YapDatabase/Utilities/YapMurmurHash.m", "/YapDatabase/Utilities/YapMurmurHash.m", "/YapDatabase/Utilities/YapMurmurHash.m"},
				},
				{
					"url":   "http://en.wikipedia.org",
					"paths": []string{"/CocoaLumberjack/DDTTYLogger.m", "/CocoaLumberjack/DDTTYLogger.m", "/CocoaLumberjack/DDTTYLogger.m"},
				},
				{
					"url": "http://enriquez.me",
					"paths": []string{
						"/Third Party Classes/ECSlidingViewController/ECPercentDrivenInteractiveTransition.m",
						"/Third Party Classes/ECSlidingViewController/ECSlidingAnimationController.m",
						"/Third Party Classes/ECSlidingViewController/ECSlidingInteractiveTransition.m",
						"/Third Party Classes/ECSlidingViewController/ECSlidingSegue.m",
						"/Third Party Classes/ECSlidingViewController/ECSlidingViewController.m",
						"/Third Party Classes/ECSlidingViewController/UIViewControllerxECSlidingViewController.m",
					},
				},
			},
		},
		"files": map[string]interface{}{
			"certs": []string{},
			"plist": []string{"/iVim/Info.plist", "/iVim/Settings.bundle/Root.plist", "/iVim/systemFonts.plist",
				"/iVim.xcodeproj/project.xcworkspace/xcshareddata/IDEWorkspaceChecks.plist",
			},
		},
		"plist": map[string]interface{}{
			"id":                         "com.terrychou.ivim",
			"build":                      "1",
			"sdk":                        "iphonesimulator12.1",
			"platform":                   "12.1",
			"minimum_version":            "9.1",
			"bundle_name":                "iVim",
			"bundle_version_name":        "1",
			"bundle_supported_platforms": []string{"iPhoneSimulator"},
			"bundle_localizations":       []string{"es"},
			"insecure_connections": map[string]interface{}{
				"allow_arbitrary_loads": false,
				"domains":               []string{},
			},
		},
		"virus": map[string]interface{}{
			"total":       54,
			"positives":   0,
			"verbose_msg": "Scan finished, information embedded",
			"scans": map[string]interface{}{
				"ALYac": map[string]interface{}{
					"detected": false,
					"result":   "",
					"update":   "20190812",
					"version":  "1.1.1.5",
				},
				"Ad-Aware": map[string]interface{}{
					"detected": false,
					"result":   "",
					"update":   "20190813",
					"version":  "3.0.5.370",
				},
			},
		},
		"lookup": map[string]interface{}{
			"count":   0,
			"results": []map[string]interface{}{},
		},
	}
)

func TestStaticAnalysisTransformation(t *testing.T) {
	p, err := (&StaticAnalysis{}).FromMap(staticAnalysisTestMap)
	assert.NoError(t, err)
	st := staticAnalysisTestMap
	st["has_binary"] = true
	st["has_code"] = true
	st["has_files"] = true
	st["has_plist"] = true
	st["has_virus"] = true
	st["has_store"] = true
	assert.Equal(t, staticAnalysisTestMap, p.ToMap())
}

func TestStaticAnalysisValidation(t *testing.T) {
	p, err := (&StaticAnalysis{}).FromMap(staticAnalysisTestMap)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 0)
	p, err = (&StaticAnalysis{}).FromMap(wrongStaticAnalysisTestMap)
	assert.NoError(t, err)
	assert.Len(t, p.Validate(), 33)
}
