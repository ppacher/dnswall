package zone

import (
	"github.com/homebot/dnswall"
	"github.com/homebot/dnswall/request"
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
func (p *Provider) Serve(session *dnswall.Session, req *request.Request) error {
	for _, zone := range p.zones {
		// TODO(ppacher): we are using the first zone that is a parent of the request
		// however, check if we may have a better match (deligation in the parent zone)
		if dns.IsSubDomain(zone.Name.String(), req.Name().String()) {
			rr, ok := zone.Lookup(req.Class(), req.Type(), req.Name())
			if !ok {
				// No not pass the request down the middleware handler as
				// we are the responsible zone handler
				return session.Reject(dns.RcodeNameError)
			}

			return session.Resolve(dns.RcodeSuccess, rr, nil)
		}
	}

	// Nothing found, continue middleware stack
	return session.Next()
}
