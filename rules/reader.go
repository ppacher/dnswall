package rules

import (
	"bufio"
	"io"
	"os"
)

// ParseRules parses a set of rules from an io.Reader
func ParseRules(r io.Reader) ([]*Rule, error) {
	scanner := bufio.NewScanner(r)
	var rules []*Rule

	for scanner.Scan() {
		rule, err := NewRule(scanner.Text())
		if err != nil {
			return nil, err
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

// ReadRules parses a set of rules from the given file
func ReadRules(f string) ([]*Rule, error) {
	r, err := os.Open(f)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	return ParseRules(r)
}
