# coredns-redis

`coredns-redis` is a CoreDNS plug-in that implements a protocol gateway
between DNS and [Redis](https://redis.io/). This plug-in uses the least
amount of intelligence as possible:

* No data is cached by the plug-in; however the CoreDNS `cache` plug-in
  can be used
* A very small subset of the DNS protocol is implemented: only SOA, NS
  and A records are currently supported
* Zone transfer and other fancy features are explictly ignored
* DNS TTL support is implemented by relying on Redis EXPIRE/TTL commands

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

## Configuration

This plugin should be located right next to `etcd` in `plugins.cfg`:

```
...
secondary:secondary
etcd:etcd
redis:github.com/grafanalf/coredns-redis/redis
loop:loop
forward:forward
grpc:grpc
...
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

## configuration

```
{
  redis {
    address HOST:PORT
    username USER
    password PASSWORD
    connect_timeout TIME_MS
    read_timeout TIME_MS
    ttl TIME_S
    prefix PREFIX
  }
}
```

- `address` is the address of the redis backend in form of *host:port* (defaults to `localhost:6379`)
- `username` is the username for connectiong to the redis backend (optional)
- `password` is the redis password (optional)
- `connect_timeout` maximum time to establish a connection to the redis backend (in ms, optional)
- `read_timeout` maximum time to wait for the redis backend to respond (in ms, optional)
- `ttl` default ttl for dns records which have no ttl set (in seconds, default 3600)
- `prefix` a prefix added to all redis keys

### example

corefile:
```
{
  .{
    redis {
      address localhost:6379
      username redis_user
      password super_secret
      connect_timeout 2000
      read_timeout 2000
      ttl 300
      prefix DNS_
    }
  }
}
```

## reverse zones

not yet supported


## proxy

not yet supported

## API

Package `redis` provides functions to manipulate (get, add, edit, delete) the data in the redis backend.
The DNS zones are saved as hashmaps with the zone-name as key in the backend.
While the data format is JSON at the moment, but I am considering switching to 
*protobuf* for performance reasons later. 

## credits

this plugin started as a fork of [github.com/arvancloud/redis](https://github.com/arvancloud/redis).

