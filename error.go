package govh

import (
	"fmt"
)

// ApiOvhError is a struct representing an error that can occured while calling API.
type ApiOvhError struct {
	// Error message.
	Message string
	// HTTP code.
	Code int
	// Unique request tracer.
	Tracer string
}

func (err *ApiOvhError) Error() string {
	return fmt.Sprintf("Error %d : %s", err.Code, err.Message)
}
