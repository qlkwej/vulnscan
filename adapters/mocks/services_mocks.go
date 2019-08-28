package mocks

import (
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
	"github.com/stretchr/testify/assert"
)

func MalwareDomainsAdapter(command utils.Command, entity *entities.CodeAnalysis) error {
	entity.BadDomains = []string{
		"ru.theswiftones.com",
		"www.litra.com.mk/wp-sts.php",
		"dancecourt.com",
		"www.profill-smd.com",
		"sandiego_court.com",
		"www.pretty_cinderella.ru",
		"rage_against_the_machine.jp",
	}
	return nil
}

func VirusTotalAdapter(command utils.Command, entity *entities.VirusAnalysis) error {
	assert.NotEmpty(command.T, command.VirusTotalKey)
	entity = &entities.VirusAnalysis{
		HasReport: true,
		Response: entities.VirusResponse{
			ResponseCode: 1,
			VerboseMsg:   "Scan finished, information embedded",
			Resource:     "b956666c9670cff7166d28af88a3e063",
			ScanId:       "11ff8b84c2dd786d259ace96c7a658e79a667d76db33fc3b2f1b021504d03144-1565653959",
			Sha256:       "11ff8b84c2dd786d259ace96c7a658e79a667d76db33fc3b2f1b021504d03144",
			Permalink:    "https://www.virustotal.com/file/11ff8b84c2dd786d259ace96c7a658e79a667d76db33fc3b2f1b021504d03144/analysis/1565653959/",
		},
		Report: entities.VirusReport{
			VirusResponse: entities.VirusResponse{
				ResponseCode: 1,
				VerboseMsg:   "Scan finished, information embedded",
				Resource:     "b956666c9670cff7166d28af88a3e063",
				ScanId:       "11ff8b84c2dd786d259ace96c7a658e79a667d76db33fc3b2f1b021504d03144-1565653959",
				Sha256:       "11ff8b84c2dd786d259ace96c7a658e79a667d76db33fc3b2f1b021504d03144",
				Permalink:    "https://www.virustotal.com/file/11ff8b84c2dd786d259ace96c7a658e79a667d76db33fc3b2f1b021504d03144/analysis/1565653959/",
			},
			Md5:       "b956666c9670cff7166d28af88a3e063",
			Sha1:      "01d4f5b3a7d81a02c8be039124c08a0e389f3eb3",
			ScanDate:  "2019-08-12 23:52:39",
			Positives: 0,
			Total:     54,
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
	return nil
}
