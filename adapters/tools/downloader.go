package tools

import (
	"fmt"
	"github.com/simplycubed/vulnscan/entities"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)


func DownloaderAdapter(command entities.Command, entity *entities.ToolUrls) error {
	var errors = map[string]error{}
	for desc, url := range entity.ToMap() {
		resp, err := http.Get(url.(string))
		if err != nil {
			errors[desc] = err
			continue
		}

		out, err := os.Create(filepath.Join(command.Tools, desc))
		if err != nil {
			errors[desc] = err
			continue
		}

		// Write the body to file
		_, err = io.Copy(out, resp.Body)
		if err != nil {
			errors[desc] = err
		}
		_ = out.Close()
		_ = resp.Body.Close()

	}
	if len(errors) > 0 {
		var sb strings.Builder
		sb.WriteString("unable to download some tools: ")
		for k, v := range errors {
			sb.WriteString(fmt.Sprintf("%s: %s", k, v))
		}
		return fmt.Errorf(sb.String())
	}
	return nil
}
