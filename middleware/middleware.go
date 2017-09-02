package middleware

import "golang.org/x/net/context"
import "git.vie.cybertrap.com/ppacher/dnslog/request"
import "github.com/miekg/dns"

// Middleware is a middleware for DNS servers
type Middleware interface {
	// Name returns the name of the middleware
	Name() string

	// Serve serves the given DNS request. If a *dns.Msg is returned,
	// the request will be served and middleware handler below will
	// not be executed. If an error is returned, the request will be
	// aborted. If neither a *dns.Msg nor a error is returned, the
	// request will be passed through the next middleware handlers
	Serve(context.Context, *request.Request) (context.Context, *dns.Msg, error)

	// Mangle is called for each middleware that have served a request but
	// not provided a response or error
	Mangle(context.Context, *request.Request, *dns.Msg) error
}
