package rules

import (
	"errors"
	"fmt"
	"sync"

	"git.vie.cybertrap.com/ppacher/dnslog/request"

	"github.com/Knetic/govaluate"
	"github.com/miekg/dns"
)

var functions = map[string]govaluate.ExpressionFunction{
	// Verdict functions
	"accept":   accept,
	"reject":   reject,
	"mark":     mark,
	"sinkhole": sinkhole,

	// Utility methods
	"isSubdomain":         isSubdomain,
	"inNetwork":           inNetwork,
	"isSubdomainFromList": isSubDomainFromList,
}

// Context represents an additional context for evaluating rules
type Context struct {
	// Parameters are passed down to the rule evaluator
	// Note that passing maps is not yet supported by govaluate
	Parameters map[string]interface{}
}

type Expr struct {
	expr *govaluate.EvaluableExpression

	consts map[string]interface{}
}

// Question is the struct passed during rule evaluation
type Question struct {
	Name  string
	Type  string
	Class string
}

// NewExpr creates a new evaluable DNS expression
func NewExpr(expr string, consts ...map[string]interface{}) (*Expr, error) {
	e, err := govaluate.NewEvaluableExpressionWithFunctions(expr, functions)
	if err != nil {
		return nil, err
	}

	params := make(map[string]interface{})

	for _, c := range consts {
		for key, value := range c {
			params[key] = value
		}
	}

	return &Expr{
		expr:   e,
		consts: params,
	}, nil
}

// Evaluate evalutes the expression against the given request and
// returns the result
func (e *Expr) Evaluate(req *request.Request, resp *dns.Msg, ctx ...Context) (interface{}, error) {
	params := map[string]interface{}{
		"request": Question{
			Name:  req.Name().String(),
			Class: req.Class().String(),
			Type:  req.Type().String(),
		},
		"clientIP": req.ClientIP(),
	}

	if resp != nil {
		params["response"] = resp
	}

	for key, value := range e.consts {
		params[key] = value
	}

	for _, c := range ctx {
		for key, val := range c.Parameters {
			params[key] = val
		}
	}

	return e.expr.Evaluate(params)
}

// Verdict evaluates the rule and returns the final verdict
func (e *Expr) Verdict(req *request.Request, resp *dns.Msg, ctx ...Context) (Verdict, error) {
	res, err := e.Evaluate(req, resp, ctx...)
	if err != nil {
		return nil, err
	}

	v, ok := res.(Verdict)
	if !ok {
		return v, nil
	}

	return nil, fmt.Errorf("invalid result type for verdict: %#v", res)
}

// EvaluateBool evaluates the expression against the DNS request and
// returns the result (which should be a boolean)
func (e *Expr) EvaluateBool(req *request.Request, resp *dns.Msg, ctx ...Context) (bool, error) {
	ret, err := e.Evaluate(req, resp, ctx...)
	if err != nil {
		return false, err
	}

	if b, ok := ret.(bool); ok {
		return b, nil
	}

	return false, errors.New("invalid return value")
}

// Rule evaluates a govaluate expression and returns the resulting
// verdict. It also keeps track of various metrics
type Rule struct {
	expresion string
	compiled  *Expr

	rw      sync.RWMutex
	matches int
}

// NewRule returns a new rule for the given expression and providing the keys
// in the `consts` map array to each evaluation
func NewRule(expr string, consts ...map[string]interface{}) (*Rule, error) {
	comp, err := NewExpr(expr, consts...)
	if err != nil {
		return nil, err
	}

	return &Rule{
		expresion: expr,
		compiled:  comp,
		matches:   0,
	}, nil
}

// Verdict evaluates the rule for the given request and response messages
// and returns the result
func (rule *Rule) Verdict(req *request.Request, resp *dns.Msg, ctx ...Context) (Verdict, error) {
	v, err := rule.compiled.Verdict(req, resp, ctx...)
	if err != nil {
		return v, err
	}

	if _, ok := v.(Noop); ok {
		return v, err
	}

	rule.rw.Lock()
	defer rule.rw.Unlock()

	rule.matches++

	return v, err
}

// Matches returns the number of times the rule returned a verdict
// (other than Noop)
func (rule *Rule) Matches() int {
	rule.rw.RLock()
	defer rule.rw.RUnlock()

	return rule.matches
}
