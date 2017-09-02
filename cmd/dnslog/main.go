package main

import (
	"log"

	"git.vie.cybertrap.com/ppacher/dnslog/forwarder"
	logMw "git.vie.cybertrap.com/ppacher/dnslog/log"
	"git.vie.cybertrap.com/ppacher/dnslog/server"
	"git.vie.cybertrap.com/ppacher/dnslog/sinkhole"
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

	sink, err := sinkhole.New("127.0.0.1", "isSubdomain(request.Name, 'orf.at')")
	if err != nil {
		log.Fatal(err)
	}

	z, err := zone.LoadZoneFile("/tmp/zone", "example.com.")
	if err != nil {
		log.Fatal(err)
	}

	provider := zone.NewProvider(z)

	srv.Use(
		&logMw.LogMiddleware{},
		sink,
		provider,
		resolver,
	)

	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
