package zone

import (
	"fmt"

	"golang.org/x/net/context"

	"github.com/homebot/dnswall/request"
	"github.com/homebot/dnswall/server"
	"github.com/miekg/dns"
)

// Provider is a DNS server middleware that resolves queries for
// registered zones
type Provider struct {
	zones []*Zone
}

func NewProvider(z ...*Zone) *Provider {
	return &Provider{
		zones: z,
	}
}

func (p *Provider) Name() string {
	return "zone"
}

// Serve serves the DNS request and implements middleware.Middleware
func (p *Provider) Serve(ctx context.Context, req *request.Request) server.Result {
	for _, zone := range p.zones {
		if dns.IsSubDomain(zone.Name.String(), req.Name().String()) {
			rr, ok := zone.Lookup(req.Class(), req.Type(), req.Name())
			if !ok {
				resp := req.CreateError(dns.RcodeNameError)
				return server.Resolve(ctx, req, resp, fmt.Sprintf("zone:%s", zone.Name))
			}

			resp := new(dns.Msg)
			resp.SetRcode(req.Req, dns.RcodeSuccess)

			resp.Answer = make([]dns.RR, len(rr))
			for idx, r := range rr {
				resp.Answer[idx] = r
			}

			return server.Resolve(ctx, req, resp, fmt.Sprintf("zone:%s", zone.Name))
		}
	}

	// Nothing found, continue middleware stack
	return server.FailOrNext(ctx)
}

// Mangle does nothing in the zone provider and implements middleware.Middleware
func (p *Provider) Mangle(ctx context.Context, req *request.Request, response *dns.Msg) error {
	return nil
}
