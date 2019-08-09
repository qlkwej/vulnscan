package entities

import "gopkg.in/go-playground/validator.v9"



// The interface entity is intended to make easier the communication with external world in a generic way.
type Entity interface {
	// ToMap allows the different entities to be transformed to map[string]interface{} objects without using reflection.
	ToMap() map[string]interface{}
	// ToMap and FromMap are complementary functions, in order to test them, we have to be sure that a FromMap().ToMap()
	// roundtrip outputs the same map object as the used input.
	FromMap(m map[string]interface{}) Entity
	// Validate allows to obtain an array of field errors from the Entity fields. It allows to check if the entity
	// creation has been completelly succesful or not.
	Validate() []validator.FieldError
}

var validate *validator.Validate

func getValidator() *validator.Validate {
	if validate == nil {
		validate = validator.New()
		_ = validate.RegisterValidation("valid_bits", bitsValidator)
		_ = validate.RegisterValidation("valid_endianness", endiannessValidator)
		_ = validate.RegisterValidation("valid_status", statusValidator)
		_ = validate.RegisterValidation("valid_cpu", cpuValidator)
		_ = validate.RegisterValidation("valid_sub_cpu", subCpuValidator)
	}
	return validate
}


func Validate(e Entity) []validator.FieldError {
	err := validate.Struct(e)
	if err != nil {
		return err.(validator.ValidationErrors)
	}
	return []validator.FieldError{}
}

