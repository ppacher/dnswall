package rules

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// IsSubDomain checks if child is a sub domain of parent
func IsSubDomain(parent, child string) (bool, error) {
	return dns.IsSubDomain(parent, child), nil
}

func isSubdomain(args ...interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, errors.New("isSubdomain(): invalid usage of isSubdomain")
	}

	what, ok := args[0].(string)
	if !ok {
		return nil, errors.New("isSubdomain(): first parameter must be a string")
	}

	parent, ok := args[1].(string)
	if !ok {
		return nil, errors.New("isSubdomain(): second parameter must be a string")
	}

	return IsSubDomain(parent, what)
}

// InNetwork checks if target is inside network
// `target` and `network` may be IPv4 or IPv6 address where the network is specified using
// CIDR notation (e.g. target=192.168.0.1, network=192.168.129/25)
// For IPv4, the network can also be in "nmap like" sub-range format
// For example, target=192.168.0.1, network=192.168.0-10.11-100
func InNetwork(target, network string) (bool, error) {
	ip := net.ParseIP(target)
	if ip == nil {
		return false, errors.New("invalid target IP")
	}

	// We first always try to parse RFC confirm CIDR notation
	// e.g. 192.168.0.1/24
	_, n, err := net.ParseCIDR(network)
	if err != nil {
		// if we failed to parse CIDR, we check for IPv4 sub-range notation
		// e.g. 192.168.0-4.1-10
		ipParts := strings.Split(target, ".")
		if len(ipParts) != 4 {
			return false, errors.New("invalid format for target IP (must be IPv4 for sub-range checks)")
		}

		netParts := strings.Split(network, ".")
		if len(netParts) != 4 {
			return false, errors.New("invalid network address. Must either be CIDR (IPv4 or IPv6) or sub-range (IPv4, eg 192.168.1-3.10-12) format")
		}

		for idx, part := range ipParts {
			if netParts[idx] != part {
				octet, err := strconv.ParseInt(ipParts[idx], 10, 64)
				if err != nil {
					return false, err
				}

				netoctets := strings.Split(netParts[idx], "-")
				if len(netoctets) == 1 {
					// just one octet, we should have matched during the string compare
					return false, nil
				}

				if len(netoctets) != 2 {
					return false, fmt.Errorf("invalid network sub-range: %v", netoctets)
				}

				lower, err := strconv.ParseInt(netoctets[0], 10, 64)
				if err != nil {
					return false, fmt.Errorf("invalid network sub-range: %s: %s", netoctets[0], err)
				}

				higher, err := strconv.ParseInt(netoctets[1], 10, 64)
				if err != nil {
					return false, fmt.Errorf("invalid network sub-range: %s: %s", netoctets[1], err)
				}

				if octet < lower || octet > higher {
					return false, nil
				}
			}
		}
		return false, err
	}

	return n.Contains(ip), nil
}

func inNetwork(args ...interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, errors.New("inNetwork(): invalid usage")
	}

	target, ok := args[0].(string)
	if !ok {
		return nil, errors.New("inNetwork(): first parameter must be a string")
	}

	network, ok := args[1].(string)
	if !ok {
		return nil, errors.New("inNetwork(): second parameter must be a string")
	}

	return InNetwork(target, network)
}

// IsSubDomainFromList checks if child is a subdomain from one of the
// parents
func IsSubDomainFromList(child string, parents []string) bool {
	for _, p := range parents {
		if ok, err := IsSubDomain(p, child); ok && err == nil {
			return true
		}
	}
	return false
}

func isSubDomainFromList(args ...interface{}) (interface{}, error) {
	var list []string

	for idx, a := range args {
		s, ok := a.(string)

		if !ok {
			return nil, fmt.Errorf("isSubDomainFromList(): invalid type for parameter %d", idx)
		}

		list = append(list, s)
	}

	if len(list) < 2 {
		return nil, fmt.Errorf("isSubDomainFromList(): invalid number of parameters")
	}

	target := list[1]
	parents := list[1:]

	return IsSubDomainFromList(target, parents), nil
}
