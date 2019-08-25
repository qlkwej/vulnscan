package output

import (
	"encoding/json"
	"fmt"
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
	"os"
)

func JsonAdapter(command utils.Command, entity entities.Entity) (entities.Entity, error) {
	out, err := json.MarshalIndent(entity.ToMap(), "", "  ")
	if err != nil {
		return entity, err
	}
	_, err = fmt.Fprint(os.Stdout, out)
	return entity, err
}
