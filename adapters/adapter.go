package adapters

import (
	"github.com/simplycubed/vulnscan/entities"
	"github.com/simplycubed/vulnscan/utils"
)

type Adapter func(command utils.Command, entity entities.Entity) (entities.Entity, error)
