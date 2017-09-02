package sinkhole

import (
	"fmt"
	"log"
	"net"

	"golang.org/x/net/context"

	"git.vie.cybertrap.com/ppacher/dnslog/request"
	"git.vie.cybertrap.com/ppacher/dnslog/rules"
	"github.com/miekg/dns"
)

type Sinkhole struct {
	destination string

	expressions []*rules.Expr
}

func New(dest string, expr ...string) (*Sinkhole, error) {
	s := &Sinkhole{
		destination: dest,
	}

	for _, e := range expr {
		compiled, err := rules.New(e)
		if err != nil {
			return nil, err
		}

		s.expressions = append(s.expressions, compiled)
	}

	return s, nil
}

func (s *Sinkhole) Serve(ctx context.Context, req *request.Request) (context.Context, *dns.Msg, error) {
	for idx, rule := range s.expressions {
		res, err := rule.EvaluateBool(req)
		if err != nil {
			log.Printf("[sinkhole] Error during rule %d: %s\n", idx, err)
			continue
		}

		if res {
			repl := new(dns.Msg)
			repl.SetReply(req.Req)

			if len(req.Req.Question) > 0 {
				repl.Answer = make([]dns.RR, 1)

				repl.Answer[0] = &dns.A{
					A: net.ParseIP(s.destination),
					Hdr: dns.RR_Header{
						Name:   req.Name().String(),
						Class:  uint16(req.Class()),
						Rrtype: uint16(req.Type()),
					},
				}
			}

			return ctx, repl, nil
		}
	}

	return ctx, nil, nil
}

func (s *Sinkhole) Mangle(ctx context.Context, req *request.Request, response *dns.Msg) error {
	return nil
}

func (s *Sinkhole) Name() string {
	return fmt.Sprintf("sinkhole:%s", s.destination)
}
