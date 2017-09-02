package main

import (
	"log"

	"git.vie.cybertrap.com/ppacher/dnslog/forwarder"
	logMw "git.vie.cybertrap.com/ppacher/dnslog/log"
	"git.vie.cybertrap.com/ppacher/dnslog/rules"
	"git.vie.cybertrap.com/ppacher/dnslog/server"
	"git.vie.cybertrap.com/ppacher/dnslog/zone"
)

func main() {
	srv := server.New()

	srv.WithTCP(nil)
	srv.WithUDP(nil)

	resolver, err := forwarder.New([]string{"8.8.8.8:53"}, map[string]string{
		"8.8.4.4:53": "accept(isSubdomain(request.Name, 'orf.at'))",
	})
	if err != nil {
		log.Fatal(err)
	}

	z, err := zone.LoadZoneFile("/tmp/zone", "example.com.")
	if err != nil {
		log.Fatal(err)
	}

	provider := zone.NewProvider(z)

	r, _ := rules.NewRule("reject(isSubdomain(request.Name, 'orf.at'))")
	input := []*rules.Rule{
		r,
	}
	output := []*rules.Rule{}

	engine := rules.NewEngine(rules.Accept{}, rules.Accept{}, input, output)

	srv.Use(
		&logMw.LogMiddleware{},
		engine,
		provider,
		resolver,
	)

	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
