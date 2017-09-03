package server

import "golang.org/x/net/context"
import "github.com/homebot/dnswall/request"
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
	Serve(context.Context, *request.Request) Result

	// Mangle is called for each middleware that have served a request but
	// not provided a response or error
	Mangle(context.Context, *request.Request, *dns.Msg) error
}

type Result struct {
	ctx  context.Context
	err  error
	resp *request.Response
}

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

func FailOrNext(ctx context.Context) Result {
	return Result{
		ctx: ctx,
	}
}

func Abort(ctx context.Context, err error) Result {
	return Result{
		ctx: ctx,
		err: err,
	}
}
