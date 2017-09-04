package main

import (
	"fmt"
	"log"
	"net/url"
	"strings"

	"github.com/alecthomas/kingpin"

	"github.com/homebot/dnswall/cache"
	"github.com/homebot/dnswall/forwarder"
	logMw "github.com/homebot/dnswall/log"
	"github.com/homebot/dnswall/rules"
	"github.com/homebot/dnswall/server"
	"github.com/homebot/dnswall/zone"
)

var (
	inputRules  string
	outputRules string
	zoneFile    string
	zoneName    string
	forwarders  []string
	forwardIf   []string
	listen      []string
	listenAll   bool
)

func init() {
	kingpin.Flag("input-rules", "File containing input rules").Short('i').StringVar(&inputRules)
	kingpin.Flag("output-rules", "File containing output rules").Short('o').StringVar(&outputRules)
	kingpin.Flag("zone", "File contain the DNS zone to serve (bind format)").Short('z').StringVar(&zoneFile)
	kingpin.Flag("origin", "Zone origin").Short('n').StringVar(&zoneName)
	kingpin.Flag("forwarder", "Forwarder DNS servers to use").Short('f').StringsVar(&forwarders)
	kingpin.Flag("forward-if", "Conditional forwarders in format host:port=condtion").Short('F').StringsVar(&forwardIf)
	kingpin.Flag("listen", "Addresses to listen on").Short('l').StringsVar(&listen)
	kingpin.Flag("listen-all", "Listen on 0.0.0.0:53 for UDP and TCP").Short('L').BoolVar(&listenAll)
}

func main() {
	kingpin.Parse()

	srv := server.New()

	listeners := 0

	if listenAll {
		listen = []string{"udp://:53", "tcp://:53"}
	}

	for _, l := range listen {
		u, err := url.Parse(l)
		if err != nil {
			log.Fatal(fmt.Errorf("listen: %q invalid format: %s", l, err))
		}

		switch u.Scheme {
		case "tcp":
			opt := server.Options{
				Addr: u.Host,
			}

			srv.WithTCP(&opt)
			listeners++
		case "udp":
			opt := server.Options{
				Addr: u.Host,
			}

			srv.WithUDP(&opt)
			listeners++
		default:
			log.Fatal(fmt.Errorf("listen: invalid or unsupported scheme: %s", l))
		}
	}

	if listeners == 0 {
		log.Println("No listener specified. Using --listen udp://127.0.0.1:5353")
		srv.WithUDP(&server.Options{
			Addr: "127.0.0.1:5353",
		})
	}

	stack := []server.Middleware{
		&logMw.LogMiddleware{},
	}
	var err error

	// Rule middleware
	var input []*rules.Rule
	if inputRules != "" {
		input, err = rules.ReadRules(inputRules)
		if err != nil {
			log.Fatal(fmt.Errorf("error parsing input rules: %s", err))
		}
	}

	var output []*rules.Rule
	if outputRules != "" {
		output, err = rules.ReadRules(outputRules)
		if err != nil {
			log.Fatal(fmt.Errorf("error parsing output rules: %s", err))
		}
	}

	engine := rules.NewEngine(rules.Accept{}, rules.Accept{}, input, output)
	stack = append(stack, engine)

	// Zone middleware
	if zoneName != "" && zoneFile != "" {
		z, err := zone.LoadZoneFile(zoneFile, zoneName)
		if err != nil {
			log.Fatal(fmt.Errorf("error paring zone file: %s", err))
		}

		stack = append(stack, zone.NewProvider(z))
	}

	cacheMw := cache.New()
	stack = append(stack, cacheMw)

	conditionalForwarders := make(map[string]string)

	for _, fi := range forwardIf {
		parts := strings.Split(fi, "=")
		if len(parts) < 2 {
			log.Fatal(fmt.Errorf("forward-if: %q has invalid format", fi))
		}

		host := parts[0]
		condition := strings.Join(parts[1:], "=")

		conditionalForwarders[host] = condition
	}

	// Forwarder middleware
	if len(forwarders) > 0 || len(conditionalForwarders) > 0 {
		resolver, err := forwarder.New(forwarders, conditionalForwarders)
		if err != nil {
			log.Fatal(fmt.Errorf("forwarder: invalid configuration: %s", err))
		}
		stack = append(stack, resolver)
	}

	srv.Use(stack...)

	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
