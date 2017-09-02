package rules

import (
	"context"
	"log"
	"sync"

	"git.vie.cybertrap.com/ppacher/dnslog/request"
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
func (ng *Engine) Serve(ctx context.Context, req *request.Request) (context.Context, *dns.Msg, error) {
	// TODO: implement
	return nil, nil, nil
}

// Mangle mangles the response to a DNS request by evaluating the output chain
func (ng *Engine) Mangle(ctx context.Context, req *request.Request, resp *dns.Msg) error {
	// TODO: implement
	return nil
}
