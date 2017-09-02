package main

import (
	"log"

	"github.com/alecthomas/kingpin"

	"git.vie.cybertrap.com/ppacher/dnslog/forwarder"
	logMw "git.vie.cybertrap.com/ppacher/dnslog/log"
	"git.vie.cybertrap.com/ppacher/dnslog/rules"
	"git.vie.cybertrap.com/ppacher/dnslog/server"
	"git.vie.cybertrap.com/ppacher/dnslog/zone"
)

var (
	inputRules  string
	outputRules string
	zoneFile    string
	zoneName    string
)

func init() {
	kingpin.Flag("input-rules", "File containing input rules").Short('i').StringVar(&inputRules)
	kingpin.Flag("output-rules", "File containing output rules").Short('o').StringVar(&outputRules)
	kingpin.Flag("zone", "File contain the DNS zone to serve (bind format)").Short('z').StringVar(&zoneFile)
	kingpin.Flag("origin", "Zone origin").Short('n').StringVar(&zoneName)
}

func main() {
	kingpin.Parse()

	srv := server.New()
	srv.WithTCP(nil)
	srv.WithUDP(nil)

	stack := []server.Middleware{
		&logMw.LogMiddleware{},
	}
	var err error

	// Rule middleware
	var input []*rules.Rule
	if inputRules != "" {
		input, err = rules.ReadRules(inputRules)
		if err != nil {
			log.Fatal(err)
		}
	}

	var output []*rules.Rule
	if outputRules != "" {
		output, err = rules.ReadRules(outputRules)
		if err != nil {
			log.Fatal(err)
		}
	}

	engine := rules.NewEngine(rules.Accept{}, rules.Accept{}, input, output)
	stack = append(stack, engine)

	// Zone middleware
	if zoneName != "" && zoneFile != "" {
		z, err := zone.LoadZoneFile(zoneFile, zoneName)
		if err != nil {
			log.Fatal(err)
		}

		stack = append(stack, zone.NewProvider(z))
	}

	// Forwarder middleware
	resolver, err := forwarder.New([]string{"8.8.8.8:53"}, map[string]string{
		"8.8.4.4:53": "accept(isSubdomain(request.Name, 'orf.at'))",
	})
	if err != nil {
		log.Fatal(err)
	}
	stack = append(stack, resolver)

	srv.Use(stack...)

	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
