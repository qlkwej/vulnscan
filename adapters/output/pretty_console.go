package output

import (
	"fmt"
	"github.com/gookit/color"
	"os"
	"strconv"
	"strings"

	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
)

func ConsoleAdapter(command utils.Command, entity entities.Entity) (entities.Entity, error) {
	var e error
	switch entity.(type) {
	case *entities.BinaryAnalysis:
		_, e = color.Fprintf(os.Stdout, createBinaryOutput(entity.(*entities.BinaryAnalysis)))
	case *entities.CodeAnalysis:
		_, e = color.Fprintf(os.Stdout, createCodeOutput(entity.(*entities.CodeAnalysis)))
	case *entities.FileAnalysis:
		_, e = color.Fprintf(os.Stdout, createFilesOutput(entity.(*entities.FileAnalysis)))
	case *entities.PListAnalysis:
		_, e = color.Fprintf(os.Stdout, createPlistOutput(entity.(*entities.PListAnalysis)))
	case *entities.StoreAnalysis:
		_, e = color.Fprintf(os.Stdout, createStoreOutput(entity.(*entities.StoreAnalysis)))
	case *entities.VirusAnalysis:
		_, e = color.Fprintf(os.Stdout, createVirusOutput(entity.(*entities.VirusAnalysis)))
	case *entities.StaticAnalysis:
		_, e = color.Fprintf(os.Stdout, createStaticOutput(entity.(*entities.StaticAnalysis)))
	default:
		e = fmt.Errorf("printing error: unable to detect analysis kind")
	}
	return entity, e
}

func createStaticOutput(entity *entities.StaticAnalysis) string {
	var sb strings.Builder
	if entity.HasBinary {
		sb.WriteString(createBinaryOutput(&entity.Binary))
	}
	if entity.HasStore {
		sb.WriteString(createStoreOutput(&entity.Store))
	}
	if entity.HasFiles {
		sb.WriteString(createFilesOutput(&entity.Files))
	}
	if entity.HasPlist {
		sb.WriteString(createPlistOutput(&entity.Plist))
	}
	if entity.HasCode {
		sb.WriteString(createCodeOutput(&entity.Code))
	}
	if entity.HasVirus {
		sb.WriteString(createVirusOutput(&entity.Virus))
	}
	return sb.String()
}

func createVirusOutput(entity *entities.VirusAnalysis) string {
	var (
		sb strings.Builder
		responseMap = entity.Response.ToMap()
	)
	getResponseData := func() {
		for _, s := range []string{"scan_id", "permalink"} {
			sb.WriteString(pretifyKey(s))
			sb.WriteString(responseMap[s].(string))
		}
	}
	sb.WriteString(title("Virus analysis"))
	if entity.HasReport {
		reportMap := entity.Report.ToMap()
		sb.WriteString("Virus scan has been completed, results:\n\n")
		sb.WriteString(subTitle("General information"))
		getResponseData()
		for _, s := range []string{"md5", "sha1", "scan_date"} {
			sb.WriteString(pretifyKey(s))
			sb.WriteString(value(reportMap[s].(string)))
		}
		sb.WriteString(key("Number of scans performed"))
		sb.WriteString(value(strconv.Itoa(entity.Report.Total)))
		sb.WriteString(key("Number of positives"))
		sb.WriteString(value(strconv.Itoa(entity.Report.Positives)))
		for n, s := range entity.Report.Scans {
			sb.WriteString(subTitle(fmt.Sprintf("Analysis name: %s\n", n)))
			sb.WriteString(key("Detected"))
			if s.Detected{
				sb.WriteString(value("True"))
			} else {
				sb.WriteString(value("False"))
			}
			for k, v := range s.ToMap() {
				if k != "detected" {
					sb.WriteString(pretifyKey(k))
					sb.WriteString(value(v.(string)))
				}
			}
		}
	} else {
		sb.WriteString("Virus scan has been submited, but it's not complete yet. Please, visit the scan url to see the" +
			"results or repeat the scan later:\n\n")
	}
	return sb.String()
}

func createStoreOutput(entity *entities.StoreAnalysis) string {
	var sb strings.Builder
	sb.WriteString(title("Information found on app store"))
	sb.WriteString(key("Number of results found"))
	sb.WriteString(value(strconv.Itoa(entity.Count)))
	for i, r := range entity.Results {
		mapResult := r.ToMap()
		sb.WriteString(fmt.Sprintf("<bold>RESULT %s</>\n\n", strconv.Itoa(i)))
		sb.WriteString(subTitle("Basic information"))
		for _, s := range []string{"title", "app_id", "url", "price", "score"} {
			sb.WriteString(key(s))
			v := mapResult[s]
			if vt, ok :=  v.(string); ok {
				sb.WriteString(value(vt))
			} else if vt, ok := v.(float64); ok {
				sb.WriteString(value(fmt.Sprintf("%0.2f", vt)))
			}
		}
		sb.WriteString(subTitle("Developer information"))
		for _, s := range []string{"developer_id", "developer_name", "developer_url", "developer_website"} {
			sb.WriteString(key(s))
			v := mapResult[s]
			if vt, ok :=  v.(string); ok {
				sb.WriteString(value(vt))
			} else if vt, ok := v.(int); ok {
				sb.WriteString(value(fmt.Sprintf("%d", vt)))
			}
		}
		sb.WriteString(subTitle("Supported devices"))
		sb.WriteString(list(r.SupportedDevices))
		sb.WriteString(subTitle("Categories"))
		sb.WriteString(list(r.Categories))
		sb.WriteString(subTitle("Application description"))
		sb.WriteString(value(r.Description))
	}
	return sb.String()
}

func createPlistOutput(entity *entities.PListAnalysis) string {
	var sb strings.Builder
	sb.WriteString(title("Plist file analysis"))
	for k, v := range entity.ToMap() {
		if k == "xml" || k == "bundle_url_types" || k == "permissions" || k == "insecure_connections" {
			continue
		}
		sb.WriteString(pretifyKey(k))
		switch v.(type) {
		case string:
			sb.WriteString(value(v.(string)))
		case []string:
			sb.WriteString(value(""))
			sb.WriteString(list(v.([]string)))
		}
	}
	sb.WriteString(subTitle("Declared urls"))
	for _, u := range entity.BundleUrlTypes {
		sb.WriteString(key("Name"))
		sb.WriteString(value(u.Name))
		sb.WriteString(key("Schemas"))
		sb.WriteString(value(""))
		sb.WriteString(list(u.Schemas))
	}
	sb.WriteString(subTitle("Declared permissions"))
	for _, p := range entity.Permissions {
		for k, v := range p.ToMap() {
			sb.WriteString(pretifyKey(k))
			sb.WriteString(value(v.(string)))
		}
		sb.WriteString("\n")
	}
	sb.WriteString(subTitle("Insecure connections information"))
	if entity.InsecureConnections.AllowArbitraryLoads {
		sb.WriteString("<red>The app allows arbitrary web loads</>")
	} else {
		sb.WriteString("<green>The app doesn't allow arbitrary web loads</>")
	}
	sb.WriteString(key("Allowed connection domains"))
	sb.WriteString(value(""))
	sb.WriteString(list(entity.InsecureConnections.Domains))
	sb.WriteString(subTitle("Complete XML output"))
	sb.WriteString(utils.FormatXML(entity.Xml, "\t", "  "))
	return sb.String()
}

func createFilesOutput(entity *entities.FileAnalysis) string {
	var sb strings.Builder
	sb.WriteString(title("Files found in code"))
	sb.WriteString(subTitle("Certifications"))
	sb.WriteString(list(entity.Certifications))
	sb.WriteString(subTitle("Databases"))
	sb.WriteString(list(entity.Databases))
	sb.WriteString(subTitle("Plists"))
	sb.WriteString(list(entity.PLists))
	sb.WriteString(subTitle("Complete list of files"))
	sb.WriteString(list(entity.Files))
	return sb.String()
}

func createCodeOutput(entity *entities.CodeAnalysis) string {
	var sb strings.Builder
	sb.WriteString(title("Code Analysis"))
	sb.WriteString(subTitle("Traits found analyzing the code"))
	for _, c := range entity.Codes {
		for k, v := range c.CodeRule.ToMap() {
			sb.WriteString(pretifyKey(k))
			if k == "level" {
				sb.WriteString(level(entities.Level(v.(string))))
			} else {
				sb.WriteString(value(v.(string)))
			}
		}
		sb.WriteString(key("Paths where trait was found"))
		sb.WriteString(value(""))
		sb.WriteString(list(c.Paths))
		sb.WriteString("\n")
	}
	sb.WriteString(subTitle("Apis detected in code"))
	for _, a := range entity.Apis {
		sb.WriteString(key("Description"))
		sb.WriteString(value(a.Description))
		sb.WriteString(key("Paths where api was found"))
		sb.WriteString(value(""))
		sb.WriteString(list(a.Paths))
		sb.WriteString("\n")
	}
	sb.WriteString(subTitle("Urls referenced by the code"))
	for _, a := range entity.Urls {
		sb.WriteString(key("Url"))
		sb.WriteString(value(a.Url))
		sb.WriteString(key("Paths where it was found"))
		sb.WriteString(value(""))
		sb.WriteString(list(a.Paths))
		sb.WriteString("\n")
	}
	sb.WriteString(subTitle("Emails referenced by the code"))
	for _, a := range entity.Emails {
		sb.WriteString(key("Email"))
		sb.WriteString(value(a.Email))
		sb.WriteString(key("Paths where it was found"))
		sb.WriteString(value(""))
		sb.WriteString(list(a.Paths))
		sb.WriteString("\n")
	}
	return sb.String()
}

func createBinaryOutput(entity *entities.BinaryAnalysis) string {
	var sb strings.Builder
	sb.WriteString(title("Binary information"))
	sb.WriteString(key("Binary language"))
	sb.WriteString(value(string(entity.BinType)))
	for k, v := range entity.Macho.ToMap() {
		sb.WriteString(pretifyKey(k))
		sb.WriteString(value(v.(string)))
	}
	sb.WriteString(subTitle("Libraries found in the binary"))
	sb.WriteString(list(entity.Libraries))
	sb.WriteString(subTitle("Binary report results"))
	for _, r := range entity.Results {
		for k, v := range r.ToMap() {
			sb.WriteString(key(k))
			if k == "status"{
				sb.WriteString(status(entities.Status(v.(string))))
			} else {
				sb.WriteString(value(v.(string)))
			}
		}
		sb.WriteString("\n")
	}
	return sb.String()
}


func title(s string) string {
	return fmt.Sprintf("<mga>===%s===</>\n\n", s)
}

func subTitle(s string) string {
	return fmt.Sprintf("<cyan>-%s</>\n", s)
}


func key(s string) string {
	return fmt.Sprintf("<green>%s</>: ", s)
}

func pretifyKey(s string) string {
	return key(strings.Replace(strings.Title(s), "_", " ", -1))
}

func value(s string) string {
	return fmt.Sprintf("%s\n", s)
}

func list(s []string) string {
	var sb strings.Builder
	for _, e := range s {
		sb.WriteString(fmt.Sprintf("  - %s\n", e))
	}
	return sb.String()
}

func status(s entities.Status) string {
	var col string
	switch s {
	case entities.InsecureStatus:
		col = "danger"
	case entities.SecureStatus:
		col = "suc"
	case entities.WarningStatus:
		col = "warn"
	default:
		col = "default"
	}
	return value(fmt.Sprintf("<%s>%s</>", col, s))
}

func level(s entities.Level) string {
	var col string
	switch s {
	case entities.HighLevel:
		col = "danger"
	case entities.WarningLevel:
		col = "warn"
	case entities.InfoLevel:
		col = "info"
	default:
		col = "suc"
	}
	return value(fmt.Sprintf("<%s>%s</>", col, s))
}

