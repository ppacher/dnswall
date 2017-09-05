package persistence

import (
	"log"
	"time"

	"github.com/homebot/dnswall"
	"github.com/homebot/dnswall/request"
	"github.com/miekg/dns"
)

// Persister is a server.Middleware that stores DNS conversations
type Persister struct {
	storage Writer
}

// New creates a new persistence middleware with the given conversation writer
func New(storage Writer) *Persister {
	return &Persister{
		storage: storage,
	}
}

// Name returns "persistence" and implements server.Middleware
func (Persister) Name() string {
	return "persistence"
}

// Serve implements server.Middleware
func (p *Persister) Serve(session *dnswall.Session, req *request.Request) error {
	session.OnComplete(p.onComplete)
	return session.Next()
}

// Mangle implements server.Middleware and stores the conversation in the backend
func (p *Persister) onComplete(session *dnswall.Session, req *request.Request, res *dns.Msg) {
	conv := Conversation{
		Request: req,
		Response: &request.Response{
			Res: res,
		},
		Time: time.Now(),
	}

	if err := p.storage.Write(conv); err != nil {
		log.Printf("[persistence] failed to store conversation: %s\n", err)
	}
}
