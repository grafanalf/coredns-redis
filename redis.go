package redis

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/grafanalf/coredns-redis/record"
	"github.com/miekg/dns"

	redisCon "github.com/gomodule/redigo/redis"
)

const (
	// As per DNS RFC, a set of RRs shall have all their TTLs set to
	// the same value. Thats means that the TTL field should be moved
	// from the R-data structs (e.g. `A`) for those RRs that allow
	// multiple values.
	DefaultTtl        = 3600
	MaxTransferLength = 1000
)

type Redis struct {
	Pool           *redisCon.Pool
	address        string
	username       string
	password       string
	connectTimeout int
	readTimeout    int
	keyPrefix      string
	keySuffix      string
	DefaultTtl     int
}

func New() *Redis {
	return &Redis{}
}

// SetAddress sets the address (host:port) to the redis backend
func (redis *Redis) SetAddress(a string) {
	redis.address = a
}

// SetUsername sets the username for the redis connection (optional)
func (redis Redis) SetUsername(u string) {
	redis.username = u
}

// SetPassword set the password for the redis connection (optional)
func (redis *Redis) SetPassword(p string) {
	redis.password = p
}

// SetKeyPrefix sets a prefix for all redis-keys (optional)
func (redis *Redis) SetKeyPrefix(p string) {
	redis.keyPrefix = p
}

// SetKeySuffix sets a suffix for all redis-keys (optional)
func (redis *Redis) SetKeySuffix(s string) {
	redis.keySuffix = s
}

// SetConnectTimeout sets a timeout in ms for the connection setup (optional)
func (redis *Redis) SetConnectTimeout(t int) {
	redis.connectTimeout = t
}

// SetReadTimeout sets a timeout in ms for redis read operations (optional)
func (redis *Redis) SetReadTimeout(t int) {
	redis.readTimeout = t
}

// SetDefaultTtl sets a default TTL for records in the redis backend (default 3600)
func (redis *Redis) SetDefaultTtl(t int) {
	redis.DefaultTtl = t
}

// Ping sends a "PING" command to the redis backend
// and returns (true, nil) if redis response
// is 'PONG'. Otherwise Ping return false and
// an error
func (redis *Redis) Ping() (bool, error) {
	conn := redis.Pool.Get()
	defer conn.Close()

	r, err := conn.Do("PING")
	s, err := redisCon.String(r, err)
	if err != nil {
		return false, err
	}
	if s != "PONG" {
		return false, fmt.Errorf("unexpected response, expected 'PONG', got: %s", s)
	}
	return true, nil
}

func (redis *Redis) ErrorResponse(state request.Request, zone string, rcode int, err error) (int, error) {
	m := new(dns.Msg)
	m.SetRcode(state.Req, rcode)
	m.Authoritative, m.RecursionAvailable, m.Compress = true, false, true

	state.SizeAndDo(m)
	_ = state.W.WriteMsg(m)
	// Return success as the rcode to signal we have written to the client.
	return dns.RcodeSuccess, err
}

func (redis *Redis) SOA(zoneName string, rec *record.Records) (answers, extras []dns.RR) {
	soa := new(dns.SOA)

	soa.Hdr = dns.RR_Header{Name: dns.Fqdn(zoneName), Rrtype: dns.TypeSOA,
		Class: dns.ClassINET, Ttl: redis.ttl(rec.SOA.Ttl)}
	soa.Ns = rec.SOA.MName
	soa.Mbox = rec.SOA.RName
	soa.Serial = rec.SOA.Serial
	soa.Refresh = rec.SOA.Refresh
	soa.Retry = rec.SOA.Retry
	soa.Expire = rec.SOA.Expire
	soa.Minttl = rec.SOA.MinTtl
	if soa.Serial == 0 {
		soa.Serial = record.DefaultSerial()
	}
	answers = append(answers, soa)
	return
}

func (redis *Redis) A(name string, record *record.Records) (answers, extras []dns.RR) {
	for _, a := range record.A {
		if a.Ip == nil {
			continue
		}
		r := new(dns.A)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA,
			Class: dns.ClassINET, Ttl: redis.ttl(a.Ttl)}
		r.A = a.Ip
		answers = append(answers, r)
	}
	return
}

func (redis Redis) AAAA(name string, record *record.Records) (answers, extras []dns.RR) {
	for _, aaaa := range record.AAAA {
		if aaaa.Ip == nil {
			continue
		}
		r := new(dns.AAAA)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeAAAA,
			Class: dns.ClassINET, Ttl: redis.ttl(aaaa.Ttl)}
		r.AAAA = aaaa.Ip
		answers = append(answers, r)
	}
	return
}

func (redis *Redis) CNAME(name string, record *record.Records) (answers, extras []dns.RR) {
	for _, cname := range record.CNAME {
		if len(cname.Host) == 0 {
			continue
		}
		r := new(dns.CNAME)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeCNAME,
			Class: dns.ClassINET, Ttl: redis.ttl(cname.Ttl)}
		r.Target = dns.Fqdn(cname.Host)
		answers = append(answers, r)
	}
	return
}

func (redis *Redis) TXT(name string, record *record.Records) (answers, extras []dns.RR) {
	for _, txt := range record.TXT {
		if len(txt.Text) == 0 {
			continue
		}
		r := new(dns.TXT)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeTXT,
			Class: dns.ClassINET, Ttl: redis.ttl(txt.Ttl)}
		r.Txt = split255(txt.Text)
		answers = append(answers, r)
	}
	return
}

func (redis *Redis) NS(name string, zoneName string, record *record.Records, zones []string, conn redisCon.Conn) (answers, extras []dns.RR) {
	for _, ns := range record.NS {
		if len(ns.Host) == 0 {
			continue
		}
		r := new(dns.NS)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeNS,
			Class: dns.ClassINET, Ttl: redis.ttl(ns.Ttl)}
		r.Ns = ns.Host
		answers = append(answers, r)
		extras = append(extras, redis.getExtras(ns.Host, zoneName, zones, conn)...)
	}
	return
}

func (redis *Redis) MX(name string, zoneName string, record *record.Records, zones []string, conn redisCon.Conn) (answers, extras []dns.RR) {
	for _, mx := range record.MX {
		if len(mx.Host) == 0 {
			continue
		}
		r := new(dns.MX)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeMX,
			Class: dns.ClassINET, Ttl: redis.ttl(mx.Ttl)}
		r.Mx = mx.Host
		r.Preference = mx.Preference
		answers = append(answers, r)
		extras = append(extras, redis.getExtras(mx.Host, zoneName, zones, conn)...)
	}
	return
}

func (redis *Redis) SRV(name string, zoneName string, record *record.Records, zones []string, conn redisCon.Conn) (answers, extras []dns.RR) {
	for _, srv := range record.SRV {
		if len(srv.Target) == 0 {
			continue
		}
		r := new(dns.SRV)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeSRV,
			Class: dns.ClassINET, Ttl: redis.ttl(srv.Ttl)}
		r.Target = srv.Target
		r.Weight = srv.Weight
		r.Port = srv.Port
		r.Priority = srv.Priority
		answers = append(answers, r)
		extras = append(extras, redis.getExtras(srv.Target, zoneName, zones, conn)...)
	}
	return
}

func (redis *Redis) PTR(name string, zoneName string, record *record.Records, zones []string, conn redisCon.Conn) (answers, extras []dns.RR) {
	for _, ptr := range record.PTR {
		if len(ptr.Name) == 0 {
			continue
		}
		r := new(dns.PTR)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypePTR,
			Class: dns.ClassINET, Ttl: redis.ttl(ptr.Ttl)}
		r.Ptr = ptr.Name
		answers = append(answers, r)
		extras = append(extras, redis.getExtras(ptr.Name, zoneName, zones, conn)...)
	}
	return
}

func (redis *Redis) CAA(name string, record *record.Records) (answers, extras []dns.RR) {
	if record == nil {
		return
	}
	for _, caa := range record.CAA {
		if caa.Value == "" || caa.Tag == "" {
			continue
		}
		r := new(dns.CAA)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeCAA, Class: dns.ClassINET}
		r.Flag = caa.Flag
		r.Tag = caa.Tag
		r.Value = caa.Value
		answers = append(answers, r)
	}
	return
}

func (redis *Redis) getExtras(name string, zoneName string, zones []string, conn redisCon.Conn) []dns.RR {
	location := redis.FindLocation(name, zoneName)
	if location == "" {
		zoneName := plugin.Zones(zones).Matches(name)
		if zoneName == "" {
			zones, err, _ := redis.LoadZoneNamesC(name, conn)
			if err != nil {
				return nil
			}
			zoneName = plugin.Zones(zones).Matches(name)
			if zoneName == "" {
				return nil
			}
		}

		location = redis.FindLocation(name, zoneName)
		if location == "" {
			return nil
		}
		return redis.fillExtras(name, zoneName, location, conn)
	}
	return redis.fillExtras(name, zoneName, location, conn)
}

func (redis *Redis) fillExtras(name string, zoneName string, location string, conn redisCon.Conn) []dns.RR {
	var (
		zoneRecords *record.Records
		answers     []dns.RR
	)

	zoneRecords = redis.LoadZoneRecord(location, zoneName, conn)
	if zoneRecords == nil {
		return nil
	}
	a, _ := redis.A(name, zoneRecords)
	answers = append(answers, a...)
	aaaa, _ := redis.AAAA(name, zoneRecords)
	answers = append(answers, aaaa...)
	cname, _ := redis.CNAME(name, zoneRecords)
	answers = append(answers, cname...)
	return answers
}

func (redis *Redis) ttl(ttl int) uint32 {
	if ttl >= 0 {
		return uint32(ttl)
	}
	// todo: return SOA minTTL
	if redis.DefaultTtl >= 0 {
		return uint32(redis.DefaultTtl)
	}
	return DefaultTtl
}

func (redis *Redis) FindLocation(query string, zoneName string) string {
	// request for zone records
	if query == zoneName {
		return query
	}

	return strings.TrimSuffix(query, "."+zoneName)
}

// Connect establishes a connection to the redis-backend. The configuration must have
// been done before.
func (redis *Redis) Connect() error {
	redis.Pool = &redisCon.Pool{
		Dial: func() (redisCon.Conn, error) {
			var opts []redisCon.DialOption
			if redis.username != "" {
				opts = append(opts, redisCon.DialUsername(redis.username))
			}
			if redis.password != "" {
				opts = append(opts, redisCon.DialPassword(redis.password))
			}
			if redis.connectTimeout != 0 {
				opts = append(opts, redisCon.DialConnectTimeout(time.Duration(redis.connectTimeout)*time.Millisecond))
			}
			if redis.readTimeout != 0 {
				opts = append(opts, redisCon.DialReadTimeout(time.Duration(redis.readTimeout)*time.Millisecond))
			}

			return redisCon.Dial("tcp", redis.address, opts...)
		},
	}
	c := redis.Pool.Get()
	defer c.Close()

	if c.Err() != nil {
		return c.Err()
	}

	res, err := c.Do("PING")
	pong, err := redisCon.String(res, err)
	if err != nil {
		return err
	}
	if pong != "PONG" {
		return fmt.Errorf("unexpexted result, 'PONG' expected: %s", pong)
	}
	return nil
}

// DeleteZone deletes a zone-record from the backend.
func (redis *Redis) DeleteZone(zoneName string) (bool, error) {
	conn := redis.Pool.Get()
	defer conn.Close()

	reply, err := conn.Do("DEL", redis.Key(zoneName))
	i, err := redisCon.Int(reply, err)
	return i == 1, err
}

// SaveZone saves a zone-record to the backend.
func (redis *Redis) SaveZone(zone record.Zone) error {
	conn := redis.Pool.Get()
	defer conn.Close()
	for k, v := range zone.Locations {
		data, err := json.Marshal(v)
		if err != nil {
			return err
		}
		_, err = conn.Do("HSET", redis.Key(zone.Name), k, data)
		if err != nil {
			return err
		}
	}

	return nil
}

// SaveZones saves a set of zone-records to the backend.
func (redis *Redis) SaveZones(zones []record.Zone) (int, error) {
	ok := 0
	conn := redis.Pool.Get()
	defer conn.Close()

	for _, zone := range zones {
		for k, v := range zone.Locations {
			data, err := json.Marshal(v)
			if err != nil {
				return ok, err
			}
			_, err = conn.Do("HSET", redis.Key(zone.Name), k, data)
			if err != nil {
				return ok, err
			}
		}
		ok++
	}
	return ok, nil
}

func (redis *Redis) LoadZoneC(zone string, withRecord bool, conn redisCon.Conn) *record.Zone {
	z := new(record.Zone)
	z.Name = zone
	return z
}

// LoadZoneRecord loads a zone record from the backend for a given zone
func (redis *Redis) LoadZoneRecord(key string, zoneName string, conn redisCon.Conn) *record.Records {
	var (
		err   error
		reply interface{}
		val   string
	)

	var label string
	if key == zoneName {
		label = "@"
	} else {
		label = key
	}

	reply, err = conn.Do("HGET", redis.Key(zoneName), label)
	if err != nil {
		return nil
	}
	val, err = redisCon.String(reply, nil)
	if err != nil {
		return nil
	}
	r := new(record.Records)
	err = json.Unmarshal([]byte(val), r)
	if err != nil {
		fmt.Println("parse error : ", val, err)
		return nil
	}

	return r
}

// LoadAllZoneNames returns all zone names saved in the backend
func (redis *Redis) LoadAllZoneNames() ([]string, error) {
	conn := redis.Pool.Get()
	defer conn.Close()

	reply, err := conn.Do("KEYS", redis.keyPrefix+"*"+redis.keySuffix)
	zones, err := redisCon.Strings(reply, err)
	if err != nil {
		return nil, err
	}
	for i, _ := range zones {
		zones[i] = strings.TrimPrefix(zones[i], redis.keyPrefix)
		zones[i] = strings.TrimSuffix(zones[i], redis.keySuffix)
	}
	return zones, nil
}

// LoadZoneNamesC loads all zone names from the backend that are a subset from the given name.
// Therefore the name is reduced to domain and toplevel domain if necessary.
// It returns an array of zone names, an error if any and a bool that indicates if the redis
// command was executed properly
func (redis *Redis) LoadZoneNamesC(name string, conn redisCon.Conn) ([]string, error, bool) {
	var (
		reply interface{}
		err   error
		zones []string
	)

	query := reduceZoneName(name)
	if query == "" {
		query = name
	}

	reply, err = conn.Do("KEYS", redis.keyPrefix+"*"+query+redis.keySuffix)
	if err != nil {
		return nil, err, false
	}

	zones, err = redisCon.Strings(reply, err)
	if err != nil {
		return nil, err, true
	}

	for i, _ := range zones {
		zones[i] = strings.TrimPrefix(zones[i], redis.keyPrefix)
		zones[i] = strings.TrimSuffix(zones[i], redis.keySuffix)
	}
	return zones, nil, true
}

// Key returns the given key with prefix and suffix
func (redis *Redis) Key(zoneName string) string {
	return redis.keyPrefix + dns.Fqdn(zoneName) + redis.keySuffix
}

func keyExists(key string, z *record.Zone) bool {
	_, ok := z.Locations[key]
	return ok
}

func keyMatches(key string, z *record.Zone) bool {
	for value := range z.Locations {
		if strings.HasSuffix(value, key) {
			return true
		}
	}
	return false
}

// reduceZoneName strips the zone down to top- and second-level
// so we can query the subset from redis. This should give
// no problems unless we want to run a root dns
func reduceZoneName(name string) string {
	name = dns.Fqdn(name)
	split := strings.Split(name[:len(name)-1], ".")
	if len(split) == 0 {
		return ""
	}
	x := len(split) - 2
	if x > 0 {
		name = ""
		for ; x < len(split); x++ {
			name += split[x] + "."
		}
	}
	return name
}

func splitQuery(query string) (string, string, bool) {
	if query == "" {
		return "", "", false
	}
	var (
		splits            []string
		closestEncloser   string
		sourceOfSynthesis string
	)
	splits = strings.SplitAfterN(query, ".", 2)
	if len(splits) == 2 {
		closestEncloser = splits[1]
		sourceOfSynthesis = "*." + closestEncloser
	} else {
		closestEncloser = ""
		sourceOfSynthesis = "*"
	}
	return closestEncloser, sourceOfSynthesis, true
}

func split255(s string) []string {
	if len(s) < 255 {
		return []string{s}
	}
	var sx []string
	p, i := 0, 255
	for {
		if i <= len(s) {
			sx = append(sx, s[p:i])
		} else {
			sx = append(sx, s[p:])
			break

		}
		p, i = p+255, i+255
	}

	return sx
}
