package persistence

import (
	"time"

	"github.com/homebot/dnswall/request"
	"github.com/miekg/dns"
)

// Conversation is DNS request - response conversation
type Conversation struct {
	// Time the conversion happend
	Time time.Time

	// Request holds the DNS request that have been served
	Request *request.Request

	// Response holds the DNS response that ha
	Response *request.Response
}

// Writer stores a conversion
type Writer interface {
	Write(Conversation) error
}

// Iterator iterates over the result of a conversion
// query
type Iterator interface {
	// Next returns true if the next value has been loaded
	// into the iterator
	Next() bool

	// Value returns the current conversion of the iterator
	Value() Conversation
}

// Reader reads conversions from the storage
type Reader interface {
	ByClient(string) Iterator
	ByDomain(string) Iterator
	ByRequest(string, dns.Class, dns.Type) Iterator
	ByResponse(dns.Class, dns.Type, string) Iterator
}
