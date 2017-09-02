# Rule Handling

Rules are evaluable expressions executed in the context of a DNS request or response and are used to perform fine grained filtering and mangeling of DNS messages. The rule expressions are based on [govaluate](https://github.com/Knetic/govaluate).

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

## Mark

The **mark** verdict marks a request by increasing it's "evil" score and further pass it down the rules chain. This verdict may help for more fine-grained filtering support based on multiple, weighted criteria:

```javascript
// Increase the "evil" mark by 10 points and add the label "mail.ru"
// to the request
mark( isSubdomain(request.Name, "mail.ru"), 10, "mail.ru" )

// one can later use request.Mark and hasLabel() to check for 
// labels and the evil mark
reject( request.Mark > 10 || request.hasLabel("mail.ru") )
```

## Example Rules File

The following example demonstrates a simple rules file:

```javascript
// we always accept DNS queries for *.local
accept( isSubdomain(request.Name, "local.") )

// mark every thing that is not *.local with an evil score of 1 and set the "evil-by-default" label
mark( !isSubdomain(request.Name, "local."), 1, "evil-by-default")

// make sure that WannaCry will reach it's "bail-out" domain
sinkhole( request.Name == "xyz12adk48f721ndk4n1.mail.ru", "honeypod.local")

// block all other russian sites
reject( isSubdomain(request.Name, "ru") )

// most C&C server communication and DNS tunneling use very low
// TTLs so attackers can quickly change the C&C server location,
// drop everything that has a TTL lower than 10 minutes
// Note that this rule may cause troubles with some CDN providers
// that use low TTLs for fast updates (which looks like a Fast-Flux DGA network ....)
reject( request.Ttl < 60*10 )

// Sinkhole every request for which our system is 70% sure that the
// domain has been generated automatically (Domain Generation Algorithm)
sinkhole( request.DGAScore > 7 , "honeypod.local" )

// Mark request with d DGAScore > 5 as more evil
mark( request.DGAScore >= 5, 2 )

// if the request is meant for some known CDN provider, decrease it's evilness and set "cdn-provider" mark
mark( isSubdomainFromList(request.Name, "cloudfare.net", "cdn.mozilla.net", "cloud.google.com"), -2, "cdn-provider")

// Redirect all MX requests (for mail servers) comming from
// 10.172.240.0/24 to mail.local
sinkhole( inNetwork(clientIP, "10.172.240.0/24"), MX, "mail.local")

// now, reject all requests that have an evil-mark of >= 3
reject( request.Mark >= 3)

// accept the rest
accept()
```


## Rule environment

### Variables

The following variables and structures are available for rule expressions:

#### `clientIP`

Type: `string`.  
The IP address of the client that initiated the request

#### `request`

Type: `struct`

```typescript
interface Request {
    // Name requested in the DNS query
    Name: string

    // Call requested in the DNS query. Can be "IN"
    Class: string

    // Type of resource record requested. Can be "A", "AAAA", "MX", ...
    Type: string

    // Checks if the request has a given label
    hasLabel: (label: string) => boolean
}
```

#### `response`

Type: `struct`

```typescript
interface Response {
    // Resolved destination for the request. Holds data for all RRs
    // like A, AAAA, TXT, SRV, SOA, ...
    Payload: string

    // Class of the response. Mostly "IN"
    Class: string

    // Type of resource record the response contains
    Type: string

    // Time-To-Live for the resource record in seconds
    Ttl: int

    // Checks if the response has a given label
    hasLabel: (label: string) => boolean
}
```


### Functions

#### `isSubdomain(child: string, parent: string)`

Returns `true` if `child` is a sub-domain of `parent`.

   
---

#### `inNetwork(ip: string, net: string)`

Checks wheter `ip` is in `net`. Both `ip` and `net` must either be IPv4 or IPv6 addresses using their string notation (i.e. "192.168.0.1/24" or "[::fe80:00:01]/64")

   
---
   
#### `inBlockList(ip|domain: string)`

Checks whether the given IP or domain is marked as "bad" in one of the supported domain/IP block-lists

   
---

#### `tld(domain: string)`

Returns the Top-Level-Domain (TLD) of the given domain. Note that not all TLDs may be recognized and that domain registries for "sub-domains" may also be treated as TLD (i.e. `tld("test.ac.at") == "ac.at"`)


#### `isSubdomainFromList(domain: string, ...list: string)`

Returns `true` if `domain` is the a sub-domain of any parent specified in `list`. `false` otherwise.

#### `inList(what: string, ...list: string)`

Returns `true` if `what` is present in `list`. `false` otherwise.