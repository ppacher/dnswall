# dnslog

`dnslog` is a configurable DNS server with support for middleware chains. It contains an expression based rule engine for sinkholing,
forwarder selection and request filtering.

`dnslog` is currently a draft and more of a Proof-of-Concept.

More to come

### Expressions: ###

Expressions supported by the rule interface should look like the following:

```javascript
// Always allow A (rrtype=A) lookups for cybertrap.com and sub-domains
accept(request.Type == "A" && isSubdomain(request.Name, "cybertrap.com."))
```

```javascript
// reject all DNS queries from 10.172.140.150
// these will be answered with REFUSED
reject(clientIP == "10.172.140.150")
```

```javascript
// Every DNS request for *.facebook.com and facebook.com will be
// served with 127.0.0.1
sinkhole("127.0.0.1", isSubdomain("facebook.com"))
```

See [docs/README.md](docs/README.md) for more information on the (planned) rule engine.

## TODOs

- [ ] Refactored rule engine
- [ ] Middlewares: Caching
- [ ] Zone-Storage: etcd
- [ ] DNSSEC validation
- [ ] DNS query/response export/notification on AMQP/MQTT
- [ ] Management-API with plug-able transport (AMQP, gRPC, HTTP, ...)