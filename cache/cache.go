package cache

import (
	"log"
	"sync"
	"time"

	"github.com/homebot/dnswall"
	"github.com/homebot/dnswall/request"
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

func (c *Cache) Serve(session *dnswall.Session, req *request.Request) error {
	c.rw.RLock()
	defer c.rw.RUnlock()

	rrs, ok := c.records[req.Name().String()]
	if ok {
		var result []dns.RR
		for _, rr := range rrs {
			if rr.Valid() && rr.Header().Rrtype == uint16(req.Type()) && rr.Header().Class == uint16(req.Class()) {
				result = append(result, rr.RR)
			}
		}

		if len(result) > 0 {
			return session.Resolve(dns.RcodeSuccess, result, nil)
		}
	}

	// register on Complete handler to cache new RRs
	session.OnComplete(c.onComplete)

	return session.Next()
}

func (c *Cache) onComplete(session *dnswall.Session, request *request.Request, response *dns.Msg) {
	c.rw.Lock()
	defer c.rw.Unlock()

	if response != nil {
		c.cacheRRs(response.Answer)
		c.cacheRRs(response.Extra)
	}
}

func (c *Cache) cacheRRs(rrs []dns.RR) {
L:
	// TODO: there are devils inside
	for _, answer := range rrs {
		var newRRs []RR
		name := dns.Name(answer.Header().Name).String()

		for _, rr := range c.records[name] {
			if rr.Header().Rrtype == answer.Header().Rrtype && rr.Header().Class == answer.Header().Class && answer.Header().Ttl > 0 {
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
