package forwarder

import (
	"log"

	"github.com/homebot/dnswall"
	"github.com/homebot/dnswall/request"
	"github.com/homebot/dnswall/rules"
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
func (f *Forwarder) Serve(session *dnswall.Session, req *request.Request) error {
	copy := new(dns.Msg)
	req.Req.CopyTo(copy)

	if tsig := copy.IsTsig(); tsig != nil {
		// we need to clear out the Transaction signature before forwarding the request
		// to any forwarder
		copy.Extra = copy.Extra[:len(copy.Extra)-1]
	}

	// first, try to find a conditional forwarder
	for srv, expr := range f.conditionalResolvers {
		res, err := expr.EvaluateBool(req, nil)

		if err == nil && res {
			resp, err := dns.Exchange(copy, srv)
			log.Printf("[forwarder] conditional server %q selected\n", srv)
			if err != nil {
				return session.RejectError(dns.RcodeNameError, err)
			}
			return session.ResolveWith(resp)
		} else if err != nil {
			log.Printf("[forwarder] conditional expression for server %q failed to evalutate: %s\n", srv, err)
		}
	}

	for _, srv := range f.Servers {
		resp, err := dns.Exchange(copy, srv)
		if err == nil {
			log.Printf("[forwarder] resolved query for %q using %s\n", req.Name(), srv)
			return session.ResolveWith(resp)
		}

		log.Printf("[forwarder] %s: failed to resolve %q: %s\n", srv, req.Name(), err)
	}

	log.Printf("[forwarder] failed to serve request for %q. No servers available\n", req.Name())

	return session.Next()
}
