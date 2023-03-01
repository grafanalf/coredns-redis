# coredns-redis

`coredns-redis` is a CoreDNS plug-in that implements a protocol gateway
between DNS and [Redis](https://redis.io/). This plug-in uses the least
amount of intelligence as possible:

* No data is cached by the plug-in; however the CoreDNS `cache` plug-in
  can be used
* A very small subset of the DNS protocol is implemented: only SOA, NS,
  CNAME and A records are currently supported
* Zone transfer and other fancy features are explictly ignored
* DNS TTL support is implemented by relying on Redis EXPIRE/TTL commands

# Features

## DNS RRs

Minimum support for SOA, NS, A and CNAME resource records is implemented.
Documentation on how these are stored in Redis can be found below.

Note that CNAME queries are handled transparently: the DNS client will not
see the process used to resolve CNAMEs internally to a leaf A RR. This is
an opinionated decision, which probably breaks the DNS specification, but
allows concealing internal implementation details on how DNS aliasing is
implemented, and is likely irrelevant to DNS clients: in the end, they seek
an IPv4 address.

## Transport protocols

At the moment, only DNS queries are served over UDP or TCP. Other transports,
like DNS over HTTP/S or over QUIC are not supported.

## Reverse Zones

Not supported.

## Zone Transfers

Not supported.

# Redis storage definition

All DNS RRs are implemented using Redis plain key/values and ASCII literals.

The key format conforms to:

```
"[<PREFIX>:]<DNS_RR_TYPE>/<DNS_RR_FQDN>"
```

Where:

* `<PREFIX>` is an optional preffix; it might be useful when the Redis
  database is shared between multiple consumers
* `<DNS_RR_TYPE>` is the DNS RR type (e.g. `A`)
* `<DNS_RR_FQDN>` is the fully qualified name of the record, including the
  trailing dot (e.g. `bar.example.com.`).

In addition to a Redis record that stores the configuration of a DNS RR,
there might exist and additional Redis record that keeps track of its TTL.
That additiomal Redis record has a key that conforms to:

```
"[<PREFIX>:]<DNS_RR_TYPE>/<DNS_RR_FQDN>:ttl"
```

Its value is the TTL literal, and associated it has an Redis TTL expiration,
which is set by using the `EXPIRE` Redis command. The remaining TTL of such
key can be checked using the `TTL` Redis command:

```
127.0.0.1:6379> TTL "_smartdns:A/example.com.:ttl"
(integer) 119
```

The following sections describe the specification for each of the DNS RRs
that are supported:

## CNAME RR

The `CNAME` RR is special when compared to the other ones: as it behaves as
a synbolic lihk, its payload is simply the FQDN of its target or destination:

```
<FQDN>
```

Example:

```
127.0.0.1:6379> GET "_smartdns:CNAME/test.example.com."
"foo.example.com."
```

## A RR

The A RR is resolved according to the payload of its Redis record, which 
conforms to the following format:

```
<TTL> IN A <IPv4> [<IPv4> ...]
```

Where:

* `<TTL>` is the TTL associated to the record (e.g. `200`)
* `<IPv4>` is a list of IPv4 addresses to which the A RR resolves to.
  Multiple values can be supplied using a single whitespace as the delimiter.

Example:

```
127.0.0.1:6379> GET "_smartdns:A/bar.example.com."
"200 IN A 8.8.8.8 8.8.4.4"
```

## SOA RR

The SOA RR is resolved according to the payload of its Redis record, which
conforms to the following format:

```
<TTL> IN SOA <NS_NAME> <MBOX_NAME> <SERIAL> <REFRESH> <RETRY> <EXPIRE> <MINIMUM>
```

Where:

* `<TTL>` is the TTL associated to the record (e.g. `200`)
* `<NS_NAME>` is the FQDN of the name server
* `<MBOX_NAME>` is the administrator's email address, with the ‘@’ sign
  replaced with a dot.
* `<SERIAL>` is the zone serial number
* `<REFRESH>` is the length of time (in seconds) secondary servers should
  wait before asking primary servers for the SOA record to see if it has
  been updated.
* `<RETRY>` is the length of time a server should wait for asking an
  unresponsive primary nameserver for an update again.
* `<EXPIRE>` if a secondary server does not get a response from the primary
  server for this amount of time, it should stop responding to queries for
  the zone.
* `<MINIMUM>` is used in calculating the time to live for purposes of
  negative caching.

Example:

```
127.0.0.1:6379> GET "_smartdns:SOA/example.com."
"500 IN SOA foo.example.com. felipe.solana.example.com. 123000 600 600 3600 100"
```

## NS RR

The NS RR is resolved according to the payload of its Redis record, which
conforms to the following format:

```
<TTL> IN NS <NS_NAME> [<NS_NAME> ...]
```

Where:

* `<TTL>` is the TTL associated to the record (e.g. `200`)
* `<NS_NAME>` is the FQDN of the name server. Multiple values can be
  supplied using a single whitespace as the delimiter.

Example:

```
127.0.0.1:6379> GET "_smartdns:NS/example.com."
"300 IN NS foo.example.com. bar.example.com."
```

## Building CoreDNS

This plug-in is not included as part of CoreDNS and requires a custom binary
to be built with this plug-in. This plugin should be located right next to
`etcd` in `plugins.cfg`:

```diff
diff --git a/plugin.cfg b/plugin.cfg
index a7aef87d..21b106bf 100644
--- a/plugin.cfg
+++ b/plugin.cfg
@@ -63,7 +63,7 @@ file:file
 auto:auto
 secondary:secondary
 etcd:etcd
-redis:github.com/grafanalf/coredns-redis/plugin
+redis:github.com/grafanalf/coredns-redis/redis
 loop:loop
 forward:forward
 grpc:grpc
 ```

## Load-testing

> dnsperf -d loadtest -s 0.0.0.0 -p 5300 -l 60 -Q 200

Where `loadtest` is a loadtest file that looks like this:

```
foo.example.com.  A
bar.example.com.  A
example.com.      A
example.com.      SOA
example.com.      NS
```

## Configuration

This plug-in has a configuration block that begins with the reserved word
`redis` and has the following supported parameters:

```
{
  redis {
    address HOST:PORT
    [username USER]
    [password PASSWORD]
    [prefix PREFIX]
    [connect_timeout TIME_MS]
    [read_timeout TIME_MS]
    [idle_timeout TIME_MS]
    [max_active NUM_CONNS]
    [max_idle NUM_CONNS]
  }
}
```

- `address` is the address of the Redis backend in form of *host:port* (defaults to `localhost:6379`)
- `username` is the username for connectiong to the redis backend (optional)
- `password` is the redis password (optional)
- `prefix` a prefix added to all Redis keys
- `connect_timeout` maximum time to establish a connection to the Redis backend (in ms, optional)
- `read_timeout` maximum time to wait for the Redis backend to respond (in ms, optional)
- `idle_timeout` time a Redis connection needs to be idle to be closed automatically (in ms, optional)
- `max_active` maximum number of Redis connections that can be simulatenously open at any given time (integer, optional)
- `max_idle` maximum number of Redis connections in idle state (integer, optional)

### Example

corefile:
```
{
  .{
    redis example.com {
        address localhost:6379
        connect_timeout 100
        read_timeout 100
        idle_timeout 60
        max_idle 50
        max_active 1000
        prefix _DNS:
    }
  }
}
```

# Credits

This plugin started as a fork of [github.com/rverst/coredns-redis.git](https://github.com/rverst/coredns-redis).
