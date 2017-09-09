package dnswall

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/homebot/dnswall/request"
	"github.com/miekg/dns"
)

var (
	// ErrEnded is returns when the session has been marked as ended
	ErrEnded = errors.New("ended")

	// ErrNotServed is returned when no middleware handler has been able to solve the request
	ErrNotServed = errors.New("failed to serve request")
)

// CompleteFunc can be registered on a session and is called once the session has been
// resolved by a middleware
type CompleteFunc func(sess *Session, req *request.Request, res *dns.Msg)

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

	onComplete []CompleteFunc
}

// Current returns the name of the current middlware being executed
func (s *Session) Current() string {
	if s.i > len(s.handlers) {
		return ""
	}

	return s.handlers[s.i].Name()
}

// OnComplete registers a new complete handler
func (s *Session) OnComplete(fn CompleteFunc) {
	s.onComplete = append(s.onComplete, fn)
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
	return s.w.Close()
}

// TsigStatus implements dns.ResponseWriter
func (s *Session) TsigStatus() error {
	return s.w.TsigStatus()
}

// TsigTimersOnly implements dns.ResponseWriter
func (s *Session) TsigTimersOnly(b bool) {
	s.w.TsigTimersOnly(b)
}

// Prepare prepares a response message for the request
func (s *Session) Prepare() *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(s.req.Req)

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
		m.SetRcode(s.req.Req, dns.RcodeServerFailure)

		s.res = m
	}

	// execute complete handlers
	for _, fn := range s.onComplete {
		fn(s, s.req, s.res)
	}

	// if the request has been signed (and validated) using TSIG, will
	// sign the response as well
	if tsig := s.req.Req.IsTsig(); tsig != nil && s.w.TsigStatus() == nil {
		// check if the middleware has already attached a TSIG RR
		if s.res.IsTsig() == nil {
			// actuall signing will be done during WriteMsg()
			s.res.SetTsig(tsig.Header().Name, tsig.Algorithm, tsig.Fudge, time.Now().Unix())
		}
	}

	return s.w.WriteMsg(s.res)
}

// Next calls the next handler in the middleware stack
// of rails the request with ErrNotServed
func (s *Session) Next() error {
	if s.ended {
		return ErrEnded
	}

	s.i++

	if s.i >= len(s.handlers) {
		return s.RejectError(dns.RcodeServerFailure, ErrNotServed)
	}

	// Call the next handler in the stack
	return s.handlers[s.i].Serve(s, s.req)
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
func (s *Session) Reject(rcode int) error {
	m := new(dns.Msg)
	m.SetRcode(s.req.Req, rcode)

	return s.ResolveWith(m)
}

// RejectError rejects the request with the given RCode and returns the error
// to the server
func (s *Session) RejectError(rcode int, err error) error {
	m := new(dns.Msg)
	m.SetRcode(s.req.Req, rcode)

	if re := s.ResolveWith(m); re != nil {
		return re
	}

	return err
}

// Resolve resolves the request and ends the session
func (s *Session) Resolve(rcode int, answers []dns.RR, extra []dns.RR) error {
	m := new(dns.Msg)
	m.SetRcode(s.req.Req, rcode)

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
