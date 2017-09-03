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

By default, `dnslog` will listen on udp://127.0.0.1:5353. To change the behavior add the `--listen (-l)` parameter.

```bash
# Start DNS server on UDP 127.0.0.1:53 and TCP 127.0.0.1:53
./dnslog --listen udp://127.0.0.1:53 --listen tcp://127.0.0.1:53

# Short cut for UDP 0.0.0.0:53 and TCP 0.0.0.0:53
sudo ./dnslog -L
```

### Forwarders

In order to forward DNS queries to en external DNS server, append the `--forwarder` parameter. Multiple forwarders can be specified:

```bash
sudo ./dnslog -L --forwarder 8.8.8.8:53 --forwarder 8.8.4.4:53
```

#### Conditional Forwarders (Split-DNS)

`dnslog` also supports conditional forwarder selection (Split-DNS) by using the `--forward-if` command line parameter. It expects the following format: `<host>:<port>=<condition>` where `<condition>` has the same format as rules (see below) with the only difference that they should only return a boolean expression:

```bash
# All request for sub-domains of cybertrap.com should be resolved by
# 10.9.1.254:53. All other requests are forwarded to 8.8.8.8:53
sudo ./dnslog -L \
        --forwarder 8.8.8.8:53 \
        --forward-if "10.9.1.254:53=isSubdomain(request.Name, 'cybertrap.com')"

2017/09/03 12:13:12 [forwarder] conditional server "10.9.1.254:53" selected
2017/09/03 12:13:12 [forwarder] resolved request to "git.vie.cybertrap.com." (IN A) with: NOERROR: git.vie.cybertrap.com.	3600	IN	CNAME	srvcts07.vie.cybertrap.com.
2017/09/03 12:13:12 [log] [::1]:44612 requested "git.vie.cybertrap.com." class=IN type=A, resolved to: git.vie.cybertrap.com.	3600	IN	CNAME	srvcts07.vie.cybertrap.com.
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

- Middlewares: Caching
- Transaction Signatures (TSIG); Zone-transfer (AXFR) 
- TCP-TLS server support
- Zone-Storage: etcd
- DNSSEC support and validation
- Dynamic Updates (RFC2136)
- Edns0 support (RFC2671 and RFC6891)
- DNS query/response export/notification on AMQP/MQTT
- Management-API with plug-able transport (AMQP, gRPC, HTTP, ...)