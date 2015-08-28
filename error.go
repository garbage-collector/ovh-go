package govh

import "fmt"

// ApiOvhError represents an error that can occured while calling the API.
type ApiOvhError struct {
	// Error message.
	Message string
	// HTTP code.
	Code int
	// Unique request tracer.
	Tracer string
}

func (err *ApiOvhError) Error() string {
	return fmt.Sprintf("Error %d : %q", err.Code, err.Message)
}
