package zone

import (
	"golang.org/x/net/context"

	"git.vie.cybertrap.com/ppacher/dnslog/request"
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
func (p *Provider) Serve(ctx context.Context, req *request.Request) (context.Context, *dns.Msg, error) {
	for _, zone := range p.zones {
		if dns.IsSubDomain(zone.Name.String(), req.Name().String()) {
			rr, ok := zone.Lookup(req.Class(), req.Type(), req.Name())
			if !ok {
				resp := req.CreateError(dns.RcodeNameError)
				return ctx, resp, nil
			}

			resp := new(dns.Msg)
			resp.SetRcode(req.Req, dns.RcodeSuccess)

			resp.Answer = make([]dns.RR, len(rr))
			for idx, r := range rr {
				resp.Answer[idx] = r
			}

			return ctx, resp, nil
		}
	}

	// Nothing found, continue middleware stack
	return ctx, nil, nil
}

// Mangle does nothing in the zone provider and implements middleware.Middleware
func (p *Provider) Mangle(ctx context.Context, req *request.Request, response *dns.Msg) error {
	return nil
}
