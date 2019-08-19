package adapters

import "github.com/simplycubed/vulnscan/entities"

type Adapter func(entity entities.Entity) (entities.Entity, error)
