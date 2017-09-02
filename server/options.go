package server

import "time"

// Options hold generic server options for TCP and UDP
// DNS servers
type Options struct {
	// ReadTimeout for the connection
	ReadTimeout time.Duration

	// WriteTimeout for the connection
	WriteTimeout time.Duration

	// The address to listen on, defaults to ":dns"
	Addr string
}
