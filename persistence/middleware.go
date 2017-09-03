package persistence

import (
	"log"
	"time"

	"golang.org/x/net/context"

	"github.com/homebot/dnswall/request"
	"github.com/homebot/dnswall/server"
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
func (p *Persister) Serve(ctx context.Context, req *request.Request) server.Result {
	return server.FailOrNext(ctx)
}

// Mangle implements server.Middleware and stores the conversation in the backend
func (p *Persister) Mangle(ctx context.Context, req *request.Request, resp *dns.Msg) error {
	conv := Conversation{
		Request: req,
		Response: &request.Response{
			Res:        resp,
			Middleware: "not-yet-available",
		},
		Time: time.Now(),
	}

	if err := p.storage.Write(conv); err != nil {
		log.Printf("[persistence] failed to store conversation: %s\n", err)
	}

	return nil
}
