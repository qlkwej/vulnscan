package ios

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	plistlib "github.com/groob/plist"
)

// types

type CFBundleURLType struct {
	CFBundleURLName    string
	CFBundleURLSchemes []string
}

// PList

type PListPermission struct {
	Name        string
	Description string
	Reason      string
}

type PListInsecureConnections struct {
	Domains             []string
	AllowArbitraryLoads bool
}

type PList struct {
	BinName                  string
	Bin                      string
	Id                       string
	Version                  string
	Build                    string
	SDK                      string
	Platform                 string
	Min                      string
	PListXML                 string
	Permissions              []PListPermission
	InsecureConnections      PListInsecureConnections
	BundleName               string
	BundleVersionName        string
	BundleUrlTypes           []CFBundleURLType
	BundleSupportedPlatforms []string
	BundleLocalizations      []string
}

// NSAppTransportSecurityObject

type NSExceptionDomain struct {
	NSIncludesSubdomains                        bool
	NSTemporaryExceptionAllowsInsecureHTTPLoads bool
	NSTemporaryExceptionMinimumTLSVersion       string
}

type NSExceptionDomains map[string]NSExceptionDomain

type NSAppTransportSecurityObject struct {
	NSAllowsArbitraryLoads bool
	NSExceptionDomains     NSExceptionDomains
}

// PListObject

type PListObject struct {
	CFBundleDisplayName                      string
	CFBundleExecutable                       string
	CFBundleIdentifier                       string
	CFBundleVersion                          string
	DTSDKName                                string
	DTPlatformVersion                        string
	MinimumOSVersion                         string
	CFBundleName                             string
	CFBundleShortVersionString               string
	NSAppleMusicUsageDescription             string
	NSBluetoothPeripheralUsageDescription    string
	NSCalendarsUsageDescription              string
	NSCameraUsageDescription                 string
	NSContactsUsageDescription               string
	NSHealthShareUsageDescription            string
	NSHealthUpdateUsageDescription           string
	NSHomeKitUsageDescription                string
	NSLocationAlwaysUsageDescription         string
	NSLocationUsageDescription               string
	NSLocationWhenInUseUsageDescription      string
	NSMicrophoneUsageDescription             string
	NSMotionUsageDescription                 string
	NSPhotoLibraryUsageDescription           string
	NSRemindersUsageDescription              string
	NSVideoSubscriberAccountUsageDescription string
	NSAppTransportSecurity                   NSAppTransportSecurityObject
	CFBundleURLTypes                         []CFBundleURLType
	CFBundleSupportedPlatforms               []string
	CFBundleLocalizations                    []string
}

func findPListFile(src string, isSrc bool) (string, string, error) {
	var appname string
	var pListFile string
	if isSrc {
		files, err := ioutil.ReadDir(src)
		if err != nil {
			log.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".xcodeproj") {
				_, appname = filepath.Split(f.Name())
				appname = strings.Replace(appname, ".xcodeproj", "", 1)
			}
		}
		var walkErr = filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
			if !strings.Contains(path, "__MACOSX") && strings.HasSuffix(info.Name(), "Info.plist") {
				pListFile = path
			}
			if walkErr != nil {
				return walkErr
			}
			return nil
		})
	} else {
		files, err := ioutil.ReadDir(src)
		if err != nil {
			log.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".app") {
				appname = f.Name()
				break
			}
		}
		pListFile = filepath.Join(filepath.Join(src, appname), "Info.plist")
	}
	if _, err := os.Stat(pListFile); os.IsNotExist(err) {
		return "", "", fmt.Errorf("cannot find Info.plist file. Skipping PList Analysis")
	}
	return pListFile, appname, nil
}

func makePListAnalysis(pListFile, appName string, isSrc bool) (map[string]interface{}, error) {
	var plistObject PListObject
	plist := map[string]interface{}{}
	dat, err := ioutil.ReadFile(pListFile)
	if err != nil {
		return nil, fmt.Errorf("error opening Info.plist file. Skipping PList Analysis")
	}
	err = plistlib.Unmarshal(dat, &plistObject)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling Info.plist file with error %s. Skipping PList Analysis", err)
	}
	xmlBytes, err := plistlib.MarshalIndent(plistObject, "\t")
	if err != nil {
		log.Println(err)
		plist["plist_XML"] = "error"
	} else {
		plist["plist_XML"] = string(xmlBytes)
	}
	if plistObject.CFBundleDisplayName == "" {
		if !isSrc {
			plist["bin name"] = strings.Replace(appName, ".app", "", 1)
		}
	} else {
		plist["bin name"] = plistObject.CFBundleDisplayName
	}

	for k, v := range map[string]string{
		"bin":                 plistObject.CFBundleExecutable,
		"id":                  plistObject.CFBundleIdentifier,
		"build":               plistObject.CFBundleVersion,
		"sdk":                 plistObject.DTSDKName,
		"platform":            plistObject.DTPlatformVersion,
		"min":                 plistObject.MinimumOSVersion,
		"bundle_name":         plistObject.CFBundleName,
		"bundle_version_name": plistObject.CFBundleVersion,
	} {
		if v != "" {
			plist[k] = v
		}
	}
	for k, v := range map[string][]string{
		"bundle_supported_platforms": plistObject.CFBundleSupportedPlatforms,
		"bundle_localizations":       plistObject.CFBundleLocalizations,
	} {
		if len(v) != 0 {
			plist[k] = v
		}
	}
	if len(plistObject.CFBundleURLTypes) > 0 {
		urlTypes := make([]map[string]interface{}, len(plistObject.CFBundleURLTypes))
		for i, url := range plistObject.CFBundleURLTypes {
			urlTypes[i] = map[string]interface{}{}
			urlTypes[i]["name"] = url.CFBundleURLName
			urlTypes[i]["schemas"] = url.CFBundleURLSchemes
		}
		plist["bundle_url_types"] = urlTypes
	}
	if permissions := checkPermissions(&plistObject); len(permissions) > 0 {
		plist["permissions"] = permissions
	}
	plist["insecure_connections"] = checkInsecureConnections(&plistObject)
	return plist, nil
}

func PListAnalysis(src string, isSrc bool) (map[string]interface{}, error) {
	pListFile, appName, err := findPListFile(src, isSrc)
	if err != nil {
		return nil, err
	}
	return makePListAnalysis(pListFile, appName, isSrc)
}

func checkPermissions(plistObj *PListObject) []map[string]interface{} {
	var list []map[string]interface{}
	for k, v := range map[interface{}]map[string]interface{}{
		plistObj.NSAppleMusicUsageDescription: {
			"name":        "NSAppleMusicUsageDescription",
			"description": "Access Apple Media Library.",
			"reason":      plistObj.NSAppleMusicUsageDescription,
		},
		plistObj.NSBluetoothPeripheralUsageDescription: {
			"name":        "NSBluetoothPeripheralUsageDescription",
			"description": "Access Bluetooth Interface.",
			"reason":      plistObj.NSBluetoothPeripheralUsageDescription,
		},
		plistObj.NSCalendarsUsageDescription: {
			"name":        "NSCalendarsUsageDescription",
			"description": "Access Calendars.",
			"reason":      plistObj.NSCalendarsUsageDescription,
		},
		plistObj.NSCameraUsageDescription: {
			"name":        "NSCameraUsageDescription",
			"description": "Access the Camera.",
			"reason":      plistObj.NSCameraUsageDescription,
		},
		plistObj.NSContactsUsageDescription: {
			"name":        "NSContactsUsageDescription",
			"description": "Access Contacts.",
			"reason":      plistObj.NSContactsUsageDescription,
		},
		plistObj.NSHealthShareUsageDescription: {
			"name":        "NSHealthShareUsageDescription",
			"description": "Read Health Data.",
			"reason":      plistObj.NSHealthShareUsageDescription,
		},
		plistObj.NSHealthUpdateUsageDescription: {
			"name":        "NSHealthUpdateUsageDescription",
			"description": "Write Health Data.",
			"reason":      plistObj.NSHealthUpdateUsageDescription,
		},
		plistObj.NSHomeKitUsageDescription: {
			"name":        "NSHomeKitUsageDescription",
			"description": "Access HomeKit configuration data.",
			"reason":      plistObj.NSHomeKitUsageDescription,
		},
		plistObj.NSLocationAlwaysUsageDescription: {
			"name":        "NSLocationAlwaysUsageDescription",
			"description": "Access location information at all times.",
			"reason":      plistObj.NSLocationAlwaysUsageDescription,
		},
		plistObj.NSLocationUsageDescription: {
			"name":        "NSLocationUsageDescription",
			"description": "Access location information at all times (< iOS 8).",
			"reason":      plistObj.NSLocationUsageDescription,
		},
		plistObj.NSLocationWhenInUseUsageDescription: {
			"name":        "NSLocationWhenInUseUsageDescription",
			"description": "Access location information when app is in the foreground.",
			"reason":      plistObj.NSLocationWhenInUseUsageDescription,
		},
		plistObj.NSMicrophoneUsageDescription: {
			"name":        "NSMicrophoneUsageDescription",
			"description": "Access microphone.",
			"reason":      plistObj.NSMicrophoneUsageDescription,
		},
		plistObj.NSMotionUsageDescription: {
			"name":        "NSMotionUsageDescription",
			"description": "Access the device’s accelerometer.",
			"reason":      plistObj.NSMotionUsageDescription,
		},
		plistObj.NSPhotoLibraryUsageDescription: {
			"name":        "NSPhotoLibraryUsageDescription",
			"description": "Access the user’s photo library.",
			"reason":      plistObj.NSPhotoLibraryUsageDescription,
		},
		plistObj.NSRemindersUsageDescription: {
			"name":        "NSRemindersUsageDescription",
			"description": "Access the user’s reminders.",
			"reason":      plistObj.NSRemindersUsageDescription,
		},
		plistObj.NSVideoSubscriberAccountUsageDescription: {
			"name":        "NSVideoSubscriberAccountUsageDescription",
			"description": "Access the user’s TV provider account.",
			"reason":      plistObj.NSVideoSubscriberAccountUsageDescription,
		},
	} {
		if k != "" {
			list = append(list, v)
		}
	}
	return list
}

func checkInsecureConnections(plistObj *PListObject) map[string]interface{} {
	var insecureConnections = map[string]interface{}{}
	insecureConnections["allow_arbitrary_loads"] = plistObj.NSAppTransportSecurity.NSAllowsArbitraryLoads
	var domains []string
	for k := range plistObj.NSAppTransportSecurity.NSExceptionDomains {
		domains = append(domains, k)
	}
	insecureConnections["domains"] = domains
	return insecureConnections
}
