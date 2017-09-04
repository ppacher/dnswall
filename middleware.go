package dnswall

import (
	"context"
	"errors"
	"net"

	"github.com/homebot/dnswall/request"
	"github.com/miekg/dns"
)

var (
	ErrEnded     = errors.New("ended")
	ErrNotServed = errors.New("failed to serve request")
)

// Session holds metadata and additional information for
// the request being served
type Session struct {
	i        int // the current index in the handler stack
	handlers []Middleware

	w dns.ResponseWriter

	// Ctx holds the context of the session
	Ctx context.Context

	// req holds a pointer to the request of the session
	req *request.Request

	// res holds eventually holds the response for the request
	res *dns.Msg

	ended bool
}

// NewSession returns a new session for the request
func NewSession(handlers []Middleware, req *request.Request, w dns.ResponseWriter) *Session {
	return &Session{
		handlers: handlers,
		w:        w,
		Ctx:      context.Background(),
		req:      req,
	}
}

// LocalAddr implements dns.ResponseWriter
func (s *Session) LocalAddr() net.Addr {
	return s.w.LocalAddr()
}

// RemoteAddr implements dns.ResponseWriter
func (s *Session) RemoteAddr() net.Addr {
	return s.w.RemoteAddr()
}

// WriteMsg writes the message to the client
// and marks the session as ended so calls to
// Next(), Resolve(), .. fail
func (s *Session) WriteMsg(msg *dns.Msg) error {
	s.ended = true
	return s.w.WriteMsg(msg)
}

// Write buf to the client and mark the session as
// ended
func (s *Session) Write(buf []byte) (int, error) {
	s.ended = true
	return s.w.Write(buf)
}

// Hijack the session and marks it as ended. See dns.ResponseWriter
func (s *Session) Hijack() {
	s.ended = true
	s.w.Hijack()
}

// Close the session
func (s *Session) Close() error {
	s.ended = true
	return s.W.Close()
}

// TsigStatus implements dns.ResponseWriter
func (s *Session) TsigStatus() error {
	return s.w.TsigStatus()
}

// TsigTimersOnly implements dns.ResponseWriter
func (s *Session) TsigTimersOnly(b bool) error {
	return s.w.TsigTimersOnly(b)
}

// Prepare prepares a response message for the request
func (s *Session) Prepare() *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(s.req)

	return m
}

// Run the session, resolve the request and send it back
func (s *Session) Run(ctx context.Context) error {
	s.Ctx = ctx
	s.i = 0

	if len(s.handlers) == 0 {
		return errors.New("middlware stack is empty")
	}

	err := s.handlers[0].Serve(s, s.req)

	if !s.ended {
		panic("session not ended! A middleware seems to block the chain or returned without a result")
	}

	if err != nil {
		return err
	}

	if s.res == nil {
		// we failed to serve it

		m := new(dns.Msg)
		m.SetRcode(s.req, dns.RcodeServerFailure)

		s.res = m
	}

	return s.w.WriteMsg(m)
}

// Next calls the next handler in the middleware stack
// of rails the request with ErrNotServed
func (s *Session) Next() error {
	if s.ended {
		return ErrEnded
	}
	s.ended = true

	s.i++

	if s.i >= len(s.handlers) {
		s.ended = true
		return ErrNotServed
	}

	// Call the next handler in the stack
	return s.handlers[si].Serve(s, s.req)
}

// ResolveWith sets the response for the session and ends it
func (s *Session) ResolveWith(r *dns.Msg) error {
	if s.ended {
		return ErrEnded
	}
	s.ended = true

	s.res = r

	return nil
}

// Reject rejects the DNS request with the given RCode and
// ends the session
func (s *Session) Reject(rcode uint16) error {
	m := new(dns.Msg)
	m.SetRcode(s.req, rcode)

	return s.ResolveWith(m)
}

// Resolve resolves the request and ends the session
func (s *Session) Resolve(rcode uint16, answers []dns.RR, extra []dns.RR) error {
	m := new(dns.Msg)
	m.SetReply(rcode)

	m.Answer = answers
	m.Extra = extra

	return s.ResolveWith(m)
}

// Middleware is a server middleware for resolving DNS requests
type Middleware interface {
	// Name returns the name of the middleware
	Name() string

	// Serve should try to resolve the request in the session
	Serve(*Session, *request.Request) error
}
