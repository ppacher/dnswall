package zone

import (
	"errors"
	"io"
	"log"
	"os"

	"github.com/miekg/dns"
)

// Zone holds a DNS zone
type Zone struct {
	// Name holds the name of the DNS zone
	// e.g. cybertrap.com.
	Name dns.Name

	// Resources holds resources for the zone
	Resources []dns.RR
}

// Lookup searches for a RR of the given class and type within the zone
func (z Zone) Lookup(class dns.Class, rtype dns.Type, name dns.Name) ([]dns.RR, bool) {
	var results []dns.RR

	for _, rr := range z.Resources {
		log.Printf("Comparing %d=%d, %d=%d, %s=%s\n", rr.Header().Rrtype, uint16(rtype), rr.Header().Class, uint16(class), rr.Header().Name, name.String())
		if rr.Header().Rrtype == uint16(rtype) && rr.Header().Class == uint16(class) && rr.Header().Name == name.String() {
			results = append(results, rr)
		}
	}

	return results, len(results) > 0
}

// LoadZone loads a zone from the given reader
func LoadZone(origin string, r io.Reader) (*Zone, error) {
	if _, ok := dns.IsDomainName(origin); !ok {
		return nil, errors.New("invalid zone origin domain name")
	}

	z := &Zone{
		Name: dns.Name(origin),
	}

	for rr := range dns.ParseZone(r, origin, "") {
		if rr.Error != nil {
			return nil, rr.Error
		}

		log.Println(rr.RR.String())
		z.Resources = append(z.Resources, rr.RR)
	}

	return z, nil
}

// LoadZoneFile loads a DNS zone from the given file
func LoadZoneFile(file string, origin string) (*Zone, error) {
	r, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	return LoadZone(origin, r)
}
