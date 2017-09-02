package rules

import (
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

func accept(args ...interface{}) (interface{}, error) {
	if len(args) == 0 {
		return Accept{}, nil
	}

	if len(args) > 1 {
		return nil, errors.New("accept(): invalid number arguments")
	}

	b, ok := args[0].(bool)
	if !ok {
		return nil, errors.New("accept(): wrong type for parameter 1")
	}

	if b {
		return Accept{}, nil
	}

	return Noop{}, nil
}

func reject(args ...interface{}) (interface{}, error) {
	if len(args) == 0 {
		return Reject{
			Code: dns.RcodeRefused,
		}, nil
	}

	if len(args) > 2 {
		return nil, errors.New("reject(): invalid number of arguments")
	}

	b, ok := args[0].(bool)
	if !ok {
		return nil, errors.New("reject(): wrong type for parameter 1")
	}

	code := dns.RcodeRefused

	if len(args) == 2 {
		c, ok := args[1].(int)
		if !ok {
			return nil, errors.New("reject(): wront type for parameter 2")
		}

		code = c
	}

	if b {
		return Reject{
			Code: code,
		}, nil
	}

	return Noop{}, nil
}

func sinkhole(args ...interface{}) (interface{}, error) {
	if len(args) < 2 {
		return nil, errors.New("sinkhole(): invalid number of parameters")
	}

	b, ok := args[0].(bool)
	if !ok {
		return nil, errors.New("sinkhole(): wrong type for parameter 1")
	}

	dest, ok := args[1].(string)
	if !ok {
		return nil, errors.New("sinkhole(): wrong type for parameter 2")
	}

	if b {
		return Sinkhole{
			Destination: dest,
		}, nil
	}

	return Noop{}, nil
}

func mark(args ...interface{}) (interface{}, error) {
	var labels []string
	amount := 1
	match := true

	if len(args) >= 1 {
		b, ok := args[0].(bool)
		if !ok {
			return nil, errors.New("mark(): wrong type for parameter 1")
		}

		match = b
	}

	if len(args) >= 2 {
		a, ok := args[0].(int)
		if !ok {
			return nil, errors.New("mark(): wrong type for parameter 2")
		}
		amount = a

		for idx, a := range args[2:] {
			l, ok := a.(string)
			if !ok {
				return nil, fmt.Errorf("mark(): wrong type for parameter %d", idx+1)
			}

			labels = append(labels, l)
		}
	}

	if match {
		return Mark{
			Amount: amount,
			Labels: labels,
		}, nil
	}

	return Noop{}, nil
}
