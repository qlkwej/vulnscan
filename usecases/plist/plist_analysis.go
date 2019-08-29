package plist

import (
	"fmt"
	"github.com/simplycubed/vulnscan/adapters"
	"github.com/simplycubed/vulnscan/adapters/output"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
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

// ParsedPList

type ParsedPList struct {
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

// Looks for the plist file in the folder. Depending on the isSrc flag, parses the folder differently.
func findPListFile(command *utils.Command) error {
	var plistPath string
	files, err := ioutil.ReadDir(command.Path)
	if err != nil {
		return fmt.Errorf("error reading the directory %s: %s", command.Path, err)
	}
	if command.Source {
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".xcodeproj") {
				_, appname := filepath.Split(f.Name())
				command.AppName = strings.Replace(appname, ".xcodeproj", "", 1)
			}
		}
		walkErr := filepath.Walk(command.Path, func(path string, info os.FileInfo, err error) error {
			if !strings.Contains(path, "__MACOSX") && strings.HasSuffix(info.Name(), "Info.plist") {
				plistPath = path
			}
			if err != nil {
				return err
			}
			return nil
		})
		if walkErr != nil {
			return fmt.Errorf("error walking directory %s: %s", command.Path, walkErr)
		}

	} else {
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".app") {
				command.AppName = f.Name()
				break
			}
		}
		plistPath = filepath.Join(filepath.Join(command.Path, command.AppName), "Info.plist")
	}
	if _, err := os.Stat(plistPath); os.IsNotExist(err) {
		return fmt.Errorf("cannot find Info.plist file. Skipping PList Analysis")
	}
	command.Path = plistPath
	return nil
}

// Performs the plist analysis. Extracts information from the plist file found in the binary/source. This function
// is extracted from the main Analysis function in order to ease testing.
func makePListAnalysis(command utils.Command, entity *entities.PListAnalysis, adapter adapters.AdapterMap) {
	var (
		plistObject  ParsedPList
		analysisName = entities.Plist
	)
	_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "parsing plist file..."))
	dat, err := ioutil.ReadFile(command.Path)
	if err != nil {
		_ = adapter.Output.Error(output.ParseError(command, analysisName, fmt.Errorf("error opening Info.plist file: %s", err)))
		return
	}
	err = plistlib.Unmarshal(dat, &plistObject)
	if err != nil {
		_ = adapter.Output.Error(output.ParseError(command, analysisName, fmt.Errorf("error unmarshalling Info.plist file with error %s", err)))
		return
	}
	_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "plist file parsed!"))
	_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "extracting information..."))
	xmlBytes, err := plistlib.MarshalIndent(plistObject, "\t")
	if err != nil {
		log.Println(err)
		entity.Xml = "error"
	} else {
		entity.Xml = string(xmlBytes)
	}
	if plistObject.CFBundleDisplayName == "" {
		if !command.Source {
			entity.BinName = strings.Replace(command.AppName, ".app", "", 1)
		}
	} else {
		entity.BinName = plistObject.CFBundleDisplayName
	}
	entity.Bin = plistObject.CFBundleExecutable
	entity.Id = plistObject.CFBundleIdentifier
	entity.Build = plistObject.CFBundleVersion
	entity.SDK = plistObject.DTSDKName
	entity.Platform = plistObject.DTPlatformVersion
	entity.MinimumVersion = plistObject.MinimumOSVersion
	entity.BundleName = plistObject.CFBundleName
	entity.BundleVersionName = plistObject.CFBundleVersion
	entity.BundleSupportedPlatforms = plistObject.CFBundleSupportedPlatforms
	entity.BundleLocalizations = plistObject.CFBundleLocalizations
	if len(plistObject.CFBundleURLTypes) > 0 {
		entity.BundleUrlTypes = make([]entities.BundleUrlType, len(plistObject.CFBundleURLTypes))
		for i, url := range plistObject.CFBundleURLTypes {
			entity.BundleUrlTypes[i] = entities.BundleUrlType{
				Name:    url.CFBundleURLName,
				Schemas: url.CFBundleURLSchemes,
			}
		}
	}
	permissionsExtractor(&plistObject, entity)

	entity.InsecureConnections.AllowArbitraryLoads = plistObject.NSAppTransportSecurity.NSAllowsArbitraryLoads
	for k := range plistObject.NSAppTransportSecurity.NSExceptionDomains {
		entity.InsecureConnections.Domains = append(entity.InsecureConnections.Domains, k)
	}
	_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "information extracted!"))
	_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "finished"))
	if err := adapter.Output.Result(command, entity); err != nil {
		_ = adapter.Output.Error(output.ParseError(command, analysisName, err))
	}
}

// Search for the plist file calling findPListFile function and performs the PList analysis.
func Analysis(command utils.Command, entity *entities.PListAnalysis, adapter adapters.AdapterMap) {
	var analysisName = entities.Plist
	_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, "starting"))
	if adapter.Output.Error(output.ParseError(command, analysisName, findPListFile(&command))) != nil {
		return
	}
	_ = adapter.Output.Logger(output.ParseInfo(command, analysisName, fmt.Sprintf("plist file found at: %s", command.Path)))
	makePListAnalysis(command, entity, adapter)
}

// Returns an array of permissions from a plist object. Each permission is a map where the key is the permission
// description and the value a map[string]interface{} with a name, a description and a reason.
func permissionsExtractor(plistObj *ParsedPList, entity *entities.PListAnalysis) entities.Entity {
	for k, v := range map[interface{}]entities.Permission{
		plistObj.NSAppleMusicUsageDescription: {
			"NSAppleMusicUsageDescription",
			"Access Apple Media Library.",
			plistObj.NSAppleMusicUsageDescription,
		},
		plistObj.NSBluetoothPeripheralUsageDescription: {
			"NSBluetoothPeripheralUsageDescription",
			"Access Bluetooth Interface.",
			plistObj.NSBluetoothPeripheralUsageDescription,
		},
		plistObj.NSCalendarsUsageDescription: {
			"NSCalendarsUsageDescription",
			"Access Calendars.",
			plistObj.NSCalendarsUsageDescription,
		},
		plistObj.NSCameraUsageDescription: {
			"NSCameraUsageDescription",
			"Access the Camera.",
			plistObj.NSCameraUsageDescription,
		},
		plistObj.NSContactsUsageDescription: {
			"NSContactsUsageDescription",
			"Access Contacts.",
			plistObj.NSContactsUsageDescription,
		},
		plistObj.NSHealthShareUsageDescription: {
			"NSHealthShareUsageDescription",
			"Read Health Data.",
			plistObj.NSHealthShareUsageDescription,
		},
		plistObj.NSHealthUpdateUsageDescription: {
			"NSHealthUpdateUsageDescription",
			"Write Health Data.",
			plistObj.NSHealthUpdateUsageDescription,
		},
		plistObj.NSHomeKitUsageDescription: {
			"NSHomeKitUsageDescription",
			"Access HomeKit configuration data.",
			plistObj.NSHomeKitUsageDescription,
		},
		plistObj.NSLocationAlwaysUsageDescription: {
			"NSLocationAlwaysUsageDescription",
			"Access location information at all times.",
			plistObj.NSLocationAlwaysUsageDescription,
		},
		plistObj.NSLocationUsageDescription: {
			"NSLocationUsageDescription",
			"Access location information at all times (< iOS 8).",
			plistObj.NSLocationUsageDescription,
		},
		plistObj.NSLocationWhenInUseUsageDescription: {
			"NSLocationWhenInUseUsageDescription",
			"Access location information when app is in the foreground.",
			plistObj.NSLocationWhenInUseUsageDescription,
		},
		plistObj.NSMicrophoneUsageDescription: {
			"NSMicrophoneUsageDescription",
			"Access microphone.",
			plistObj.NSMicrophoneUsageDescription,
		},
		plistObj.NSMotionUsageDescription: {
			"NSMotionUsageDescription",
			"Access the device’s accelerometer.",
			plistObj.NSMotionUsageDescription,
		},
		plistObj.NSPhotoLibraryUsageDescription: {
			"NSPhotoLibraryUsageDescription",
			"Access the user’s photo library.",
			plistObj.NSPhotoLibraryUsageDescription,
		},
		plistObj.NSRemindersUsageDescription: {
			"NSRemindersUsageDescription",
			"Access the user’s reminders.",
			plistObj.NSRemindersUsageDescription,
		},
		plistObj.NSVideoSubscriberAccountUsageDescription: {
			"NSVideoSubscriberAccountUsageDescription",
			"Access the user’s TV provider account.",
			plistObj.NSVideoSubscriberAccountUsageDescription,
		},
	} {
		if k != "" {
			entity.Permissions = append(entity.Permissions, v)
		}
	}
	return entity
}
