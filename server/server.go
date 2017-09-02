package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"

	"git.vie.cybertrap.com/ppacher/dnslog/middleware"
	"git.vie.cybertrap.com/ppacher/dnslog/request"

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

	middlewares []middleware.Middleware

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
	}
	srv.udpErr = make(chan error, 1)

	return srv
}

// Use specifies the middleware stack to use
func (srv *DNSServer) Use(middlewares ...middleware.Middleware) *DNSServer {
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

	for idx, m := range srv.middlewares {
		nctx, resp, err := m.Serve(ctx, r)

		// if an error is returned, abort
		if err != nil {
			resp = r.CreateError(dns.RcodeServerFailure)
		}

		if resp != nil {
			if err == nil {
				answer := fmt.Sprintf("%s: ", dns.RcodeToString[resp.MsgHdr.Rcode])
				if len(resp.Answer) > 0 {
					answer += fmt.Sprintf("%s", resp.Answer[0].String())
				}

				log.Printf("[%s] resolved request to %q (%s %s) with: %s\n", m.Name(), r.Name(), r.Class(), r.Type(), answer)
			} else {
				log.Printf("[%s] aborted request to %q (%s %s) with error %s\n", m.Name(), r.Name(), r.Class(), r.Type(), err)
			}

			for i := idx; i >= 0; i-- {
				mangler := srv.middlewares[i]

				mangler.Mangle(ctx, r, resp)
			}

			w.WriteMsg(resp)
			return
		}

		if nctx != nil {
			ctx = nctx
		}
	}

	// if we got here, none of our middleware handlers have been able to
	// serve the request, aborting ...

	resp := r.CreateError(dns.RcodeServerFailure)
	w.WriteMsg(resp)

	return
}
