package request

import "github.com/miekg/dns"

// Response is the response to a DNS query
type Response struct {
	Res *dns.Msg

	// ServedBy holds the server address that served the request
	ServedBy string

	// Middleware holds the middleware that resolved the request
	Middleware string

	// Comment holds an additional comment by the middleware
	Comment string
}
