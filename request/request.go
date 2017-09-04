package request

import (
	"errors"
	"net"
	"strconv"

	"github.com/miekg/dns"
)

var (
	// ErrNotSigned is returned by IsSignatureValid() if the request is not
	// signed
	ErrNotSigned = errors.New("request not signed")
)

// Request is a DNS request
type Request struct {
	// W stores the response write to serve the request
	W dns.ResponseWriter

	// Mark holds the evil mark that may be adjusted
	// using a rules MARK verdict
	Mark int

	// Labels are a set of string labels appended to the request
	// Labels can be set using the MARK verdict
	Labels []string

	// Req is the actual DNS request message received
	Req *dns.Msg
}

// RemoteAddr returns the remote address of the client that
// initiated the request
func (r Request) RemoteAddr() net.Addr {
	return r.W.RemoteAddr()
}

// ClientIP returns the IP of the client that
// initiated the request
func (r Request) ClientIP() string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr().String())
	if err != nil {
		return r.RemoteAddr().String()
	}

	return ip
}

// Clone creates a copy of the request
func (r Request) Clone() *Request {
	if r.Req != nil {
		n := &Request{W: r.W, Req: r.Req.Copy()}
		return n
	}

	return &Request{W: r.W}
}

// NewWithQuestion creates a new request cloned form the old one
// but with a new question
func (r Request) NewWithQuestion(name string, qtype uint16) *Request {
	n := r.Clone()

	if n.Req == nil {
		n.Req = new(dns.Msg)
	}

	if len(n.Req.Question) < 1 {
		n.Req.Question = make([]dns.Question, 1)
	}

	n.Req.Question[0] = dns.Question{
		Name:   dns.Fqdn(name),
		Qclass: dns.ClassINET,
		Qtype:  qtype,
	}

	return n
}

// ClientPort returns the port the client used to initiate the
// request
func (r Request) ClientPort() uint16 {
	_, port, err := net.SplitHostPort(r.RemoteAddr().String())
	if err != nil {
		return 0
	}

	p, err := strconv.ParseInt(port, 10, 16)
	if err != nil {
		return 0
	}

	return uint16(p)
}

// Validate the request and return a list of errors
func (r Request) Validate() []error {
	if r.Req == nil {
		return []error{errors.New("missing request")}
	}

	if len(r.Req.Question) == 0 {
		return []error{errors.New("missing question")}
	}

	var errs []error

	for _, question := range r.Req.Question {
		if _, ok := dns.IsDomainName(question.Name); !ok {
			errs = append(errs, errors.New("invalid domain name: "+question.Name))
		}
	}

	return errs
}

// IsSigned returns true if the request is signed
func (r Request) IsSigned() bool {
	return r.Req.IsTsig() != nil
}

// IsSignatureValid returns nil if the request is signed and the signature
// is valid, an appropriate error otherwise
func (r Request) IsSignatureValid() error {
	if !r.IsSigned() {
		return ErrNotSigned
	}

	return r.W.TsigStatus()
}

// GetTsig returns the TSIG resource record if available
func (r Request) GetTsig() *dns.TSIG {
	return r.Req.IsTsig()
}

// IsValid returns true if the request is valid and can be served
func (r Request) IsValid() bool {
	return len(r.Validate()) == 0
}

// Name returns the name of the request question section
func (r Request) Name() dns.Name {
	if r.Req == nil || len(r.Req.Question) == 0 {
		return "."
	}

	return dns.Name(r.Req.Question[0].Name)
}

// Class returns the request question class
func (r Request) Class() dns.Class {
	if r.Req == nil || len(r.Req.Question) == 0 {
		return 0
	}

	return dns.Class(r.Req.Question[0].Qclass)
}

// Type returns the request question type
func (r Request) Type() dns.Type {
	if r.Req == nil || len(r.Req.Question) == 0 {
		return 0
	}

	return dns.Type(r.Req.Question[0].Qtype)
}

// CreateError creates an error response message for the request
func (r Request) CreateError(rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(r.Req, rcode)

	return m
}

// CreateResponse creates a response message for the request
// If the request has been signed, the response will be signed
// using the same TSIG key and secret
func (r Request) CreateResponse(rcode int, answer []dns.RR, extra []dns.RR) *dns.Msg {
	m := new(dns.Msg)

	m.SetReply(r.Req)

	m.Rcode = rcode
}
