package server

import (
	"github.com/homebot/dnswall/request"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

// Middleware is a middleware for DNS servers
type Middleware interface {
	// Name returns the name of the middleware
	Name() string

	// Serve serves the given DNS request. If a *dns.Msg is returned,
	// the request will be served and middleware handler below will
	// not be executed. If an error is returned, the request will be
	// aborted. If neither a *dns.Msg nor a error is returned, the
	// request will be passed through the next middleware handlers
	Serve(context.Context, *request.Request) Result

	// Mangle is called for each middleware that have served a request but
	// not provided a response or error
	Mangle(context.Context, *request.Request, request.Response) error
}

// Result is the result of a middleware
type Result struct {
	ctx  context.Context
	err  error
	resp *request.Response
}

// Resolve resolves the DNS request and should be used by middleware implementations
func Resolve(ctx context.Context, req *request.Request, resp *dns.Msg, args ...string) Result {
	result := Result{
		ctx: ctx,
	}

	comment := ""
	servedBy := ""

	if len(args) >= 1 {
		servedBy = args[0]
	}

	if len(args) >= 2 {
		comment = args[1]
	}

	result.resp = &request.Response{
		Res:      resp,
		ServedBy: servedBy,
		Comment:  comment,
	}

	return result
}

// FailOrNext fails the request if no more middleware handler is available
// Otherwise, the request is passed to the next middleware
func FailOrNext(ctx context.Context) Result {
	return Result{
		ctx: ctx,
	}
}

// Abort aborts the reqeust and returns SERVEFAIL
func Abort(ctx context.Context, err error) Result {
	return Result{
		ctx: ctx,
		err: err,
	}
}
