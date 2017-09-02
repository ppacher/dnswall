package rules

// VerdictType identifies the type of verdict
type VerdictType string

// VerdictTypes
const (
	VerdictAccept   = VerdictType("Accept")
	VerdictReject   = VerdictType("Reject")
	VerdictMark     = VerdictType("Mark")
	VerdictSinkhole = VerdictType("Sinkhole")
	VerdictNoop     = VerdictType("noop")
)

// Verdict is the result of a rule
type Verdict interface {
	// Type returns the type of verdict
	Type() VerdictType
}

// Accept represents the accept verdict
type Accept struct{}

// Type returns VerdictAccept
func (Accept) Type() VerdictType {
	return VerdictAccept
}

// Reject represents the reject verdict
type Reject struct {
	// Code is the RCode to return to the client
	Code uint16
}

// Type returns VerdictReject
func (Reject) Type() VerdictType {
	return VerdictReject
}

// Mark represents the mark verdict
type Mark struct {
	// Labels are the labels to append to the request
	Labels []string

	// Amount holds the amount to add to the evil mark
	Amount int
}

// Type returns VerdictMark
func (Mark) Type() VerdictType {
	return VerdictMark
}

// Sinkhole represents the sinkhole verdict
type Sinkhole struct {
	// Destination is the new destination of the request/response
	Destination string
}

// Type returns VerdictSinkhole
func (Sinkhole) Type() VerdictType {
	return VerdictSinkhole
}

// Noop represents no verdict
type Noop struct {
}

// Type returns VerdictNoop
func (Noop) Type() VerdictType {
	return VerdictNoop
}
