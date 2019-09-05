package output

import (
	"encoding/json"
	"fmt"
	"github.com/simplycubed/vulnscan/entities"
)

func JsonAdapter(command entities.Command, entity entities.Entity) error {
	out, err := json.MarshalIndent(entity, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(command.Output, string(out))
	return err
}
