package rules

import (
	"errors"
	"strings"

	"github.com/miekg/dns"

	"git.vie.cybertrap.com/ppacher/dnslog/request"

	"github.com/Knetic/govaluate"
)

// Constants for validating if a request should be processed
const (
	Accept = "ACCEPT"
	Drop   = "DROP"
	Reject = "REJECT"
	Nop    = ""
)

var functions = map[string]govaluate.ExpressionFunction{
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
	"accept": func(args ...interface{}) (interface{}, error) {
		if len(args) != 1 {
			return nil, errors.New("parameter 1 must be a boolean")
		}

		b, ok := args[0].(bool)
		if !ok {
			return nil, errors.New("parameter 1 must be a boolean")
		}

		if b {
			return Accept, nil
		}
		return Nop, nil
	},
	"drop": func(args ...interface{}) (interface{}, error) {
		if len(args) != 1 {
			return nil, errors.New("parameter 1 must be a boolean")
		}

		b, ok := args[0].(bool)
		if !ok {
			return nil, errors.New("parameter 1 must be a boolean")
		}

		if b {
			return Drop, nil
		}
		return Nop, nil
	},
	"reject": func(args ...interface{}) (interface{}, error) {
		if len(args) != 1 {
			return nil, errors.New("parameter 1 must be a boolean")
		}

		b, ok := args[0].(bool)
		if !ok {
			return nil, errors.New("parameter 1 must be a boolean")
		}

		if b {
			return Reject, nil
		}
		return Nop, nil
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

func IsVerdict(res interface{}, verdict string) bool {
	v, ok := res.(string)
	if !ok {
		return false
	}

	return strings.ToLower(v) == strings.ToLower(verdict)
}

func IsAccept(res interface{}) bool {
	return IsVerdict(res, Accept)
}

func IsReject(res interface{}) bool {
	return IsVerdict(res, Reject)
}

func IsDrop(res interface{}) bool {
	return IsVerdict(res, Drop)
}

func IsNop(res interface{}) bool {
	return IsVerdict(res, Nop)
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

	// check if the result is a valid verdict
	if IsAccept(ret) {
		return true, nil
	}

	if IsReject(ret) || IsDrop(ret) || IsNop(ret) {
		return false, nil
	}

	return false, errors.New("invalid return value")
}
