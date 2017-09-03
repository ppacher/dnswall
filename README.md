# dnslog

`dnslog` is a configurable DNS server with support for middleware chains. It contains an expression based rule engine for sinkholing,
forwarder selection and request filtering.

## Features

 - DNS server for TCP and UDP
 - Zone support (RFC1035; bind-style zones)
 - Static forwarders
 - Dynamic forwarder selection using rule expressions (Split-DNS)
 - Dynamic rule expressions for accepting, rejecting, marking and sinkholing (INPUT and OUTPUT chain)

## Usage

In order to download and build `dnslog` a working [Golang](https://golang.org) environment is required. Then, issue the following commands:

```bash
# Download the source code
go get git.vie.cybertrap.com/ppacher/dnslog

# Download and install dependencies
go get git.vie.cybertrap.com/ppacher/dnslog...

# Install the dnslog binary to $GOPATH/bin
go install git.vie.cybertrap.com/ppacher/dnslog/cmd/dnslog
```

### Zone-Files

Create simple zone file in RFC1035 (bind) format:

`/tmp/lab.cybertrap.com`
```
@   IN      SOA     nslab   admin.git.vie.cybertrap.com (
                                 20      ; SERIAL
                                 7200    ; REFRESH
                                 600     ; RETRY
                                 3600000 ; EXPIRE
                                 60)     ; MINIMUM

            NS      nslab
            MX      10  mail01
            MX      20  mail02

nslab       A       10.100.1.2
mail01      A       10.100.1.3
            A       10.101.1.3
mail02      A       10.100.1.4
```

Next, start `dnslog` with the zone file and the zone origin:

```bash
cd $GOPATH/bin

sudo ./dnslog --zone-file /tmp/lab.cybertrap.com --origin lab.cybertrap.com
```

Finally, we can test it:

```
dig @127.0.0.1 lab.cybertrap.com SOA
dig @127.0.0.1 nslab.cybertrap.com A
```

## Rules

`dnslog` contains two different rule chains, an INPUT and an OUTPUT chain. The INPUT chain is evaluated for each incoming DNS request and can accept, reject, sinkhole or mark the request. The OUTPUT chain is evalutated as soon as a response to the DNS request is available and can further decide to reject, sinkhole/rewrite or simply accept the response.

For more information on how to write rules, refer to the rules documentation at [docs/README.md](docs/README.md).

Let's create a simple rules file for the INPUT chain:

`/tmp/input`
```typescript
// 10.0.1.11 is our virus-test host, sinkhole all DNS requests from this IP to 1.2.3.4 and block everything that go for *.cybertrap.com
sinkhole( clientIP == "10.0.1.11", "1.2.3.4" )
reject( clientIP == "10.0.1.11" && isSubdomain(request.Name, "cybertrap.com") )

// Accept all requests that go for *.lab.cybertrap.com without
// any further processing
accept( isSubdomain(request.Name, "lab.cybertrap.com.") )
```

Finally, start up DNS log and pass in the path to the input rules file:

```bash
sudo ./dnslog --input-rules /tmp/input --forwarder 8.8.8.8:53
```


## Roadmap

- [ ] Middlewares: Caching
- [ ] TCP-TLS server support
- [ ] Zone-Storage: etcd
- [ ] DNSSEC support and validation
- [ ] Dynamic Updates (RFC2136)
- [ ] Edns0 support (RFC2671 and RFC6891)
- [ ] DNS query/response export/notification on AMQP/MQTT
- [ ] Management-API with plug-able transport (AMQP, gRPC, HTTP, ...)