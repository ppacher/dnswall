package rules

import (
	"log"
	"sync"

	"github.com/homebot/dnswall"
	"github.com/homebot/dnswall/request"
	"github.com/miekg/dns"
)

// Chain is a chain of rules
// TODO(ppacher): add detailed description of how a chain executes and selects
// the final verdict
type Chain struct {
	rw             sync.RWMutex
	name           string
	rules          []*Rule
	defaultVerdict Verdict
}

// NewChain returns a new chain for the given rules
func NewChain(name string, def Verdict, rules ...*Rule) *Chain {
	return &Chain{
		name:           name,
		rules:          rules,
		defaultVerdict: def,
	}
}

// Name returns the name of the chain
func (c *Chain) Name() string {
	return c.name
}

// AddRule adds a new rule to the chain
func (c *Chain) AddRule(rule *Rule) {
	c.rw.Lock()
	defer c.rw.Unlock()

	c.rules = append(c.rules, rule)
}

// Verdict evaluates the chain and returns the result
func (c *Chain) Verdict(req *request.Request, resp *dns.Msg, ctx ...Context) (Verdict, error) {
	c.rw.RLock()
	defer c.rw.RUnlock()

	for idx, rule := range c.rules {
		v, err := rule.Verdict(req, resp, ctx...)
		if err != nil {
			// continue chain but log error
			log.Printf("rule:%d failed to evaluate: %s", idx, err)
			continue
		}

		// Continue as long as
		if _, ok := v.(Noop); ok {
			continue
		}

		return v, nil
	}

	return c.defaultVerdict, nil
}

type Engine struct {
	input  *Chain
	output *Chain
}

// NewEngine returns a new engine handling both, the input and outpu
// rule chain
func NewEngine(inputDefault, outputDefault Verdict, inputChain []*Rule, outputChain []*Rule, consts ...map[string]interface{}) *Engine {
	return &Engine{
		input:  NewChain("INPUT", inputDefault, inputChain...),
		output: NewChain("OUTPUT", outputDefault, outputChain...),
	}
}

// AddInputRule adds a rule to the input chain
func (ng *Engine) AddInputRule(r *Rule) {
	ng.input.AddRule(r)
}

// AddOutputRule adds a rule to the output chain
func (ng *Engine) AddOutputRule(r *Rule) {
	ng.output.AddRule(r)
}

// VerdictInput evaluates the input chain and returns the verdict
func (ng *Engine) VerdictInput(req *request.Request, ctx ...Context) (Verdict, error) {
	return ng.input.Verdict(req, nil, ctx...)
}

// VerdictOutput evaluates the output chain and returns the verdict
func (ng *Engine) VerdictOutput(req *request.Request, resp *dns.Msg, ctx ...Context) (Verdict, error) {
	return ng.output.Verdict(req, resp, ctx...)
}

// Name returns "rules" and implements the middleware.Middleware interface
func (ng *Engine) Name() string {
	return "rules"
}

// Serve serves a DNS request by evaluating the INPUT chain
func (ng *Engine) Serve(session *dnswall.Session, req *request.Request) error {
	verdict, err := ng.input.Verdict(req, nil)
	if err != nil {
		return session.RejectError(dns.RcodeRefused, err)
	}

	// set complete handler to invoke rules in the output chain
	session.OnComplete(ng.onComplete)

	switch v := verdict.(type) {
	case Noop, Accept:
		break
	case Mark:
		req.Mark += v.Amount
	L:
		for _, l := range v.Labels {
			for _, li := range req.Labels {
				if li == l {
					continue L
				}
			}

			req.Labels = append(req.Labels, l)
		}

	case Reject:
		return session.Reject(dns.RcodeRefused)

	case Sinkhole:
		// TODO(ppacher): create response object and send it back
		return session.Reject(dns.RcodeNotImplemented)
	}

	return session.Next()
}

// Mangle mangles the response to a DNS request by evaluating the output chain
func (ng *Engine) onComplete(session *dnswall.Session, req *request.Request, res *dns.Msg) {
	verdict, err := ng.output.Verdict(req, res)
	if err != nil {
		// TODO: log error
		// clear the response message and set RcodRefused
		res.Answer = nil
		res.Extra = nil
		res.Rcode = dns.RcodeRefused
		return
	}

	switch v := verdict.(type) {
	case Noop, Accept:
		// Nothing to do in the output chain
	case Mark:
		req.Mark += v.Amount
	L:
		for _, l := range v.Labels {
			for _, li := range req.Labels {
				if li == l {
					continue L
				}
			}

			req.Labels = append(req.Labels, l)
		}

	case Reject:
		res.Rcode = v.Code
		res.Answer = nil
		res.Extra = nil

	case Sinkhole:
		// TODO(ppacher): creat response objcet and send it back
		res.Rcode = dns.RcodeNotImplemented
	}
}
