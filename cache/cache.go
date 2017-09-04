package cache

import (
	"log"
	"sync"
	"time"

	"golang.org/x/net/context"

	"github.com/homebot/dnswall/request"
	"github.com/homebot/dnswall/server"
	"github.com/miekg/dns"
)

// RR is a cached DNS resource record
type RR struct {
	Time time.Time

	dns.RR
}

// Valid returns true if the cached RR is still valid
// (TTL hasn't passed over)
func (r RR) Valid() bool {
	return r.Time.Add(time.Duration(r.RR.Header().Ttl) * time.Second).After(time.Now())
}

// NewCachedRR creates a new cached RR
func NewCachedRR(rr dns.RR) RR {
	return RR{
		Time: time.Now(),
		RR:   rr,
	}
}

// Cache is a DNS response caching middleware
type Cache struct {
	rw      sync.RWMutex
	records map[string][]RR
}

// New returns a new caching middleware
func New() *Cache {
	c := &Cache{
		records: make(map[string][]RR),
	}

	go c.cleanUp()

	return c
}

// Name returns "cache" and implements server.Middleware
func (*Cache) Name() string { return "cache" }

// Serve serves a DNS request from the cache if possible, otherwise it returns FailOrNext()
func (c *Cache) Serve(ctx context.Context, req *request.Request) server.Result {
	c.rw.RLock()
	defer c.rw.RUnlock()

	rrs, ok := c.records[req.Name().String()]
	if ok {
		var result []RR
		for _, rr := range rrs {
			if rr.Valid() && rr.Header().Rrtype == uint16(req.Type()) && rr.Header().Class == uint16(req.Class()) {
				result = append(result, rr)
			}
		}

		if len(result) > 0 {
			resp := new(dns.Msg)
			resp.SetReply(req.Req)

			resp.Answer = make([]dns.RR, len(result))
			for idx, r := range result {
				resp.Answer[idx] = r
			}

			return server.Resolve(ctx, req, resp, "cache")
		}
	}

	return server.FailOrNext(ctx)
}

// Mangle stores new RRs in the cache and implements server.Middleware
func (c *Cache) Mangle(ctx context.Context, request *request.Request, response request.Response) error {
	if response.Middleware == "cache" {
		return nil
	}

	c.rw.Lock()
	defer c.rw.Unlock()

	if response.Res != nil {
		c.cacheRRs(response.Res.Answer)
		c.cacheRRs(response.Res.Extra)
	}

	return nil
}

func (c *Cache) cacheRRs(rrs []dns.RR) {
L:
	for _, answer := range rrs {
		var newRRs []RR
		name := dns.Name(answer.Header().Name).String()

		for _, rr := range c.records[name] {
			if rr.Header().Rrtype == answer.Header().Rrtype && rr.Header().Class == answer.Header().Class {
				continue L
			}
		}

		if newRR := NewCachedRR(answer); newRR.Valid() {
			log.Printf("[cache] caching resource record: %s\n", answer.String())
			newRRs = append(newRRs, newRR)
		}

		c.records[name] = append(c.records[name], newRRs...)
	}
}

func (c *Cache) cleanUp() {
	for {
		select {
		case <-time.After(time.Second):
		}

		c.rw.Lock()

		for domain, rrs := range c.records {
			var valid []RR
			for _, rr := range rrs {
				if rr.Valid() {
					valid = append(valid, rr)
				} else {
					log.Printf("[cache] Evicted cached RR: %s", rr.String())
				}

				c.records[domain] = valid
			}
		}

		c.rw.Unlock()
	}
}
