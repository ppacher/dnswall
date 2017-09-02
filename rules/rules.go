package rules

import (
	"errors"

	"github.com/miekg/dns"

	"git.vie.cybertrap.com/ppacher/dnslog/request"

	"github.com/Knetic/govaluate"
)

var functions = map[string]govaluate.ExpressionFunction{
	// Verdict functions
	"accept":   accept,
	"reject":   reject,
	"mark":     mark,
	"sinkhole": sinkhole,

	// Utility methods
	"isSubdomain": func(args ...interface{}) (interface{}, error) {
		if len(args) != 2 {
			return nil, errors.New("invalid usage of isSubdomain")
		}

		what, ok := args[0].(string)
		if !ok {
			return nil, errors.New("first parameter must be a string")
		}

		parent, ok := args[1].(string)
		if !ok {
			return nil, errors.New("second parameter must be a string")
		}

		return dns.IsSubDomain(parent, what), nil
	},
}

type Expr struct {
	expr *govaluate.EvaluableExpression

	consts map[string]interface{}
}

type Question struct {
	Name  string
	Type  string
	Class string
}

// New creates a new evaluable DNS expression
func New(expr string, consts ...map[string]interface{}) (*Expr, error) {
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
func (e *Expr) Evaluate(req *request.Request) (interface{}, error) {
	params := map[string]interface{}{
		"request": Question{
			Name:  req.Name().String(),
			Class: req.Class().String(),
			Type:  req.Type().String(),
		},
		"clientIP": req.ClientIP(),
	}

	for key, value := range e.consts {
		params[key] = value
	}

	return e.expr.Evaluate(params)
}

// EvaluateBool evaluates the expression against the DNS request and
// returns the result (which should be a boolean)
func (e *Expr) EvaluateBool(req *request.Request) (bool, error) {
	ret, err := e.Evaluate(req)
	if err != nil {
		return false, err
	}

	if b, ok := ret.(bool); ok {
		return b, nil
	}

	return false, errors.New("invalid return value")
}
