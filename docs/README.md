# Rule Handling

Rules are evaluable expressions executed in the context of a DNS
request or response and are used to perform fine grained filtering and mangeling of DNS messages.

The rule engine of `dnslog` is similar to `iptables` in terms that it contains an INPUT and OUTPUT chain. The INPUT chain is evaluated for each DNS request and can accept, filter, sinkhole and reject DNS requests. The OUTPUT chain is evaluated for each DNS response (and the respective DNS request) and can be used to drop responses that should not be forwarded to the client.

# Rule verdicts

A verdict is the final result of a single rule. If a rule returns a matched verdict (i.e. the verdicts condition evaluates to true) the rule engine will stop further processing rules and execute the desired rule action (thus, accepting, dropping or sinkholing the request). 

## Accept

The **Accept** verdict allows the DNS request to pass the INPUT chain and be eventually resolved by one of the server's middleware.

To use the **Accept** verdict, use the provided `accept()` method passing a boolean condition:

```javascript
// Accept all requests that go for "cybertrap.com"
accept( request.Name == "cybertrap.com" )

// Accept all requests for cybertrap.com or any sub-domain
accept( isSubdomain(request.Name, "cybertrap.com") )
```

## Reject

The **Reject** verdict drops the DNS requests and sends an error response with the given RCode. If RCode is omitted, `RCodeRefused` is sent.

```javascript
// Reject all DNS queries where TTL is lower than 1 minute
// with NXDOMAIN (indicating a non-existent domain name)
reject( request.Ttl < 60, NXDOMAIN )

// Reject all russian domain requests for MX (mail) servers
reject( isSubdomain(request.Name, "ru.") && request.Type == "MX" )
```

## Sinkhole

The **Sinkhole** verdict is used to force the response message for
a DNS request. This may be useful for sinkholing malware domains and
inspecting C&C traffic:

```javascript
// Answer all requests for "badguys.it" with "10.170.250.140" if
// appropriate
// This rule will not affect IPv6 traffic unless a IPv6 target is
// specified
sinkhole( isSubdomain(request.Name, "badguys.it"), "10.170.250.140")

// Same as above but this time for IPv6
sinkhole( isSubdomain(request.Name, "badguys.it"), "[::fe80:01]")

// Sinkhole also allows matching for given request resource record
// types
sinkhole( request.Name == "facebook.com", MX, "127.0.0.1")

// Rewrite every response that would result in 1.2.3.4 to 127.0.0.1
sinkhole( response.Destination == "1.2.3.4", "127.0.0.1" )
```

## Example Rules File

The following example demonstrates a simple rules file:

```javascript
// we always accept DNS queries for *.local
accept( isSubdomain(request.Name, "local.") )

// make sure that WannaCry will reach it's "bail-out" domain
sinkhole( request.Name == "xyz12adk48f721ndk4n1.mail.ru", "honeypod.local")

// block all other russian sites
reject( isSubdomain(request.Name, "ru") )

// most C&C server communication and DNS tunneling use very low
// TTLs so attackers can quickly change the C&C server location,
// drop everything that has a TTL lower than 10 minutes
reject( request.Ttl < 60*10 )

// Sinkhole every request for which our system is 70% sure that the
// domain has been generated automatically (Domain Generation Algorithm)
sinkhole( request.DGAScore > 7 , "honeypod.local" )

// Redirect all MX requests (for mail servers) comming from
// 10.172.240.0/24 to mail.local
sinkhole( inNetwork(clientIP, "10.172.240.0/24"), MX, "mail.local")
```