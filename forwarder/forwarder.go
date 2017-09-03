package forwarder

import (
	"log"

	"golang.org/x/net/context"

	"github.com/homebot/dnswall/request"
	"github.com/homebot/dnswall/rules"
	"github.com/homebot/dnswall/server"
	"github.com/miekg/dns"
)

// Forwarder is a dnslog middleware and adds support to use forwarders
type Forwarder struct {
	Servers []string

	conditionalResolvers map[string]*rules.Expr
}

// New returns a new forwarder middleware
func New(servers []string, conditionals map[string]string) (*Forwarder, error) {
	f := &Forwarder{
		Servers:              servers,
		conditionalResolvers: make(map[string]*rules.Expr),
	}

	for key, val := range conditionals {
		expr, err := rules.NewExpr(val)
		if err != nil {
			return nil, err
		}

		f.conditionalResolvers[key] = expr
	}

	return f, nil
}

// Name returns the name of the middleware and implements middleware.Middleware
func (f *Forwarder) Name() string {
	return "forwarder"
}

// Serve the DNS request by trying to resolve the request using configured forwarders
func (f *Forwarder) Serve(ctx context.Context, req *request.Request) server.Result {

	// first, try to find a conditional forwarder
	for srv, expr := range f.conditionalResolvers {
		res, err := expr.EvaluateBool(req, nil)

		if err == nil && res {
			resp, err := dns.Exchange(req.Req, srv)
			log.Printf("[forwarder] conditional server %q selected\n", srv)
			if err != nil {
				return server.Abort(ctx, err)
			}
			return server.Resolve(ctx, req, resp, srv)
		} else if err != nil {
			log.Printf("[forwarder] conditional expression for server %q failed to evalutate: %s\n", srv, err)
		}
	}

	for _, srv := range f.Servers {
		resp, err := dns.Exchange(req.Req, srv)
		if err == nil {
			log.Printf("[forwarder] resolved query for %q using %s\n", req.Name(), srv)
			return server.Resolve(ctx, req, resp, srv)
		}

		log.Printf("[forwarder] %s: failed to resolve %q: %s\n", srv, req.Name(), err)
	}

	log.Printf("[forwarder] failed to serve request for %q. No servers available\n", req.Name())

	return server.FailOrNext(ctx)
}

// Mangle is a NOP for the forwarder middleware
func (f *Forwarder) Mangle(context.Context, *request.Request, *dns.Msg) error {
	return nil
}
