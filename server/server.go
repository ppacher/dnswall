package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/homebot/dnswall"
	"github.com/homebot/dnswall/request"

	"github.com/miekg/dns"
)

// Server is a DNS server implementation
type Server interface {
	dns.Handler
}

// DNSServer is a TCP and UDP DNS server that satisfies the Server
// interface
type DNSServer struct {
	tcp *dns.Server // The TCP server
	udp *dns.Server // The UDP server

	// Error channels for TCP and UDP server
	tcpErr chan error
	udpErr chan error

	started chan struct{}

	middlewares []dnswall.Middleware

	wg sync.WaitGroup
}

// New returns a new DNS server
func New() *DNSServer {
	return &DNSServer{
		started: make(chan struct{}),
	}
}

func (srv *DNSServer) assertNotStarted() {
	select {
	case <-srv.started:
		panic("server already started")
	default:
	}
}

// WithTCP activates the TCP server
func (srv *DNSServer) WithTCP(opts *Options) *DNSServer {
	srv.assertNotStarted()

	if opts == nil {
		// If not provided, we use the defaults from miekg/dns
		opts = &Options{}
	}

	srv.tcp = &dns.Server{
		Net:          "tcp",
		Addr:         opts.Addr,
		ReadTimeout:  opts.ReadTimeout,
		WriteTimeout: opts.WriteTimeout,
		Handler:      srv,
		TsigSecret: map[string]string{
			"test.": "dGVzdAo=",
		},
	}
	srv.tcpErr = make(chan error, 1)

	return srv
}

// WithUDP activates the UDP server
func (srv *DNSServer) WithUDP(opts *Options) *DNSServer {
	srv.assertNotStarted()

	if opts == nil {
		opts = &Options{}
	}

	srv.udp = &dns.Server{
		Net:          "udp",
		Addr:         opts.Addr,
		ReadTimeout:  opts.ReadTimeout,
		WriteTimeout: opts.WriteTimeout,
		Handler:      srv,
		TsigSecret: map[string]string{
			"test.": "dGVzdAo=",
		},
	}
	srv.udpErr = make(chan error, 1)

	return srv
}

// Use specifies the middleware stack to use
func (srv *DNSServer) Use(middlewares ...dnswall.Middleware) *DNSServer {
	srv.assertNotStarted()

	srv.middlewares = append(srv.middlewares, middlewares...)

	return srv
}

// ListenAndServe starts listening and serving the TCP and/or UDP
// server. It blocks until all servers stopped
func (srv *DNSServer) ListenAndServe() error {
	srv.assertNotStarted()

	// from now on, assertNotStarted() will panic
	close(srv.started)

	if srv.tcp != nil {
		srv.wg.Add(1)

		go func() {
			defer srv.wg.Done()

			err := srv.tcp.ListenAndServe()
			log.Printf("tcp: %s\n", err)
			srv.tcpErr <- err
		}()
	}

	if srv.udp != nil {
		srv.wg.Add(1)

		go func() {
			defer srv.wg.Done()

			err := srv.udp.ListenAndServe()
			log.Printf("udp: %s\n", err)
			srv.udpErr <- err
		}()
	}

	// Wait for all servers to shutdown
	srv.wg.Wait()

	m := ""

	// collect errors
	if srv.tcp != nil {
		if err := <-srv.tcpErr; err != nil {
			m = fmt.Sprintf("tcp: %q ", err)
		}
	}

	if srv.udp != nil {
		if err := <-srv.udpErr; err != nil {
			m += fmt.Sprintf("udp: %q", err)
		}
	}

	if m == "" {
		return nil
	}

	return errors.New(m)
}

// ServeDNS serves a DNS request and implements dns.Handler
func (srv *DNSServer) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	ctx := context.Background()

	r := &request.Request{
		W:   w,
		Req: req,
	}

	session := dnswall.NewSession(srv.middlewares, r, w)

	if err := session.Run(ctx); err != nil {
		log.Printf("Failed to serve session: %s", err)
	} else {
		log.Printf("session resolved by middleware %q", session.Current())
	}

	return
}
