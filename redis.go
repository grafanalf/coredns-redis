package redis

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin/pkg/log"
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
	MaxTransferLength = 1000
	DefaultTtl        = 3600
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
	ttlSuffix      string

	MinZoneTtl map[string]uint32

	// TODO: turn this into a LRU cache or some such
	//cachedRecords *lru.TwoQueueCache[string, *record.Records]
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

// SetTtlSuffix sets a suffix for all redis-ttls (optional)
func (redis *Redis) SetTtlSuffix(s string) {
	redis.ttlSuffix = s
}

// SetConnectTimeout sets a timeout in ms for the connection setup (optional)
func (redis *Redis) SetConnectTimeout(t int) {
	redis.connectTimeout = t
}

// SetReadTimeout sets a timeout in ms for redis read operations (optional)
func (redis *Redis) SetReadTimeout(t int) {
	redis.readTimeout = t
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
		Class: dns.ClassINET, Ttl: rec.Ttl}
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

func (redis *Redis) A(name string, zoneName string, record *record.Records) (answers, extras []dns.RR) {
	for _, a := range record.A {
		if a.Ip == nil {
			continue
		}
		r := new(dns.A)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA,
			Class: dns.ClassINET, Ttl: record.Ttl}
		r.A = a.Ip
		answers = append(answers, r)
	}
	return
}

func (redis Redis) AAAA(name string, zoneName string, record *record.Records) (answers, extras []dns.RR) {
	for _, aaaa := range record.AAAA {
		if aaaa.Ip == nil {
			continue
		}
		r := new(dns.AAAA)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeAAAA,
			Class: dns.ClassINET, Ttl: record.Ttl}
		r.AAAA = aaaa.Ip
		answers = append(answers, r)
	}
	return
}

func (redis *Redis) CNAME(name string, zoneName string, record *record.Records) (answers, extras []dns.RR) {
	for _, cname := range record.CNAME {
		if len(cname.Host) == 0 {
			continue
		}
		r := new(dns.CNAME)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeCNAME,
			Class: dns.ClassINET, Ttl: record.Ttl}
		r.Target = dns.Fqdn(cname.Host)
		answers = append(answers, r)
	}
	return
}

func (redis *Redis) TXT(name string, zoneName string, record *record.Records) (answers, extras []dns.RR) {
	for _, txt := range record.TXT {
		if len(txt.Text) == 0 {
			continue
		}
		r := new(dns.TXT)
		r.Hdr = dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeTXT,
			Class: dns.ClassINET, Ttl: record.Ttl}
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
			Class: dns.ClassINET, Ttl: record.Ttl}
		r.Ns = ns.Host
		answers = append(answers, r)
		extras = append(extras, redis.getExtras(ns.Host, zoneName, conn)...)
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
			Class: dns.ClassINET, Ttl: record.Ttl}
		r.Mx = mx.Host
		r.Preference = mx.Preference
		answers = append(answers, r)
		extras = append(extras, redis.getExtras(mx.Host, zoneName, conn)...)
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
			Class: dns.ClassINET, Ttl: record.Ttl}
		r.Target = srv.Target
		r.Weight = srv.Weight
		r.Port = srv.Port
		r.Priority = srv.Priority
		answers = append(answers, r)
		extras = append(extras, redis.getExtras(srv.Target, zoneName, conn)...)
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
			Class: dns.ClassINET, Ttl: record.Ttl}
		r.Ptr = ptr.Name
		answers = append(answers, r)
		extras = append(extras, redis.getExtras(ptr.Name, zoneName, conn)...)
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

func (redis *Redis) getExtras(name string, zoneName string, conn redisCon.Conn) []dns.RR {
	var (
		zoneRecords *record.Records
		answers     []dns.RR
	)

	// Does not support filling additional records from
	// other zones
	location := redis.FindLocation(name, zoneName)
	zoneRecords = redis.LoadZoneRecord(location, zoneName, conn)
	if zoneRecords == nil {
		return nil
	}
	a, _ := redis.A(name, zoneName, zoneRecords)
	answers = append(answers, a...)
	aaaa, _ := redis.AAAA(name, zoneName, zoneRecords)
	answers = append(answers, aaaa...)
	cname, _ := redis.CNAME(name, zoneName, zoneRecords)
	answers = append(answers, cname...)
	return answers
}

func (redis *Redis) ttl(zoneName string, ttl uint32) uint32 {
	if ttl < redis.MinZoneTtl[zoneName] {
		return redis.MinZoneTtl[zoneName]
	}
	return ttl
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

func (redis *Redis) parseRecordValuesFromString(recordType, recordName, zoneName, rData string) (answers []dns.RR, err error) {
	var (
		// array of string fiels as parsed from Redis
		// e.g. ['200', 'IN', 'A', '1.2.3.4', ...]
		fields []string
	)

	fields = strings.Fields(rData)
	if len(fields) < 4 {
		err = fmt.Errorf("error parsing RData(%s) for %s.%s: invalid number of elements", recordType, recordName, zoneName)
		return
	}
	if recordType != fields[2] {
		err = fmt.Errorf("error: mismatch record type for %s.%s: %s != %s", recordName, zoneName, recordType, fields[2])
		return
	}
	ttl, err := strconv.Atoi(fields[0])
	if err != nil {
		err = fmt.Errorf("error parsing TTL literal '%s': %s", fields[0], err)
		return
	}

	header := dns.RR_Header{
		Name:   dns.Fqdn(fmt.Sprintf("%s.%s", recordName, zoneName)),
		Rrtype: dns.TypeA,
		Class:  dns.ClassINET,
		Ttl:    uint32(ttl),
	}

	switch recordType {
	case "A":
		// Produce a RRSet with at least one record, from potentially
		// multiple IPv4 addresses
		for _, ip := range fields[3:] {
			r := new(dns.A)
			r.Hdr = header
			r.A = net.ParseIP(ip)
			answers = append(answers, r)
		}
		return
	}
	err = fmt.Errorf("Unknown record type %s", recordType)
	return
}

func (redis *Redis) LoadZoneRecord2(recordType, recordName, zoneName string, conn redisCon.Conn) ([]dns.RR, error) {
	var (
		rData        string // RR data
		remainingTtl int    // remaining TTL (from Redis)
	)

	// SOA and NS queries for the actual zone name are stored
	// in Redis (and in DNS files in general) as the `@` RR.
	if recordName == zoneName {
		recordName = "@"
	}

	err := conn.Send("MULTI")
	if err != nil {
		return nil, err
	}
	err = conn.Send("HGET", redis.Key2(zoneName), fmt.Sprintf("%s/%s", recordName, recordType))
	if err != nil {
		return nil, err
	}
	ttlKey := redis.TtlKey2(recordType, recordName, zoneName)
	err = conn.Send("TTL", ttlKey)
	if err != nil {
		return nil, err
	}
	values, err := redisCon.Values(conn.Do("EXEC"))
	if err != nil {
		return nil, err
	}
	_, err = redisCon.Scan(values, &rData, &remainingTtl)
	if err != nil {
		return nil, err
	}

	answers, err := redis.parseRecordValuesFromString(recordType, recordName, zoneName, rData)
	if err != nil {
		return nil, err
	}

	// Support for monotonically decreasing TTLs
	if remainingTtl == -2 {
		// TTL shall be the same for all records in a RRset, so we
		// take the first one
		ttl := uint32(answers[0].Header().Ttl)
		// If no Redis TTL key for the given DNS RRSet exists yet,
		// insert a special TTL key in Redis for it
		newTtl := redis.ttl(zoneName, ttl)
		_, err := conn.Do("SET", ttlKey, newTtl, "EX", newTtl)
		if err != nil {
			return nil, fmt.Errorf("error configuring RData(%s)'s TTL for %s.%s: %s", recordType, recordName, zoneName, err)
		}
	} else {
		// If a Redis TTL key for the given RRSet exists, yield
		// the remaining TTL for it
		for _, answer := range answers {
			answer.Header().Ttl = uint32(remainingTtl)
		}
	}

	return answers, nil
}

// LoadZoneRecord loads a zone record from the backend for a given zone
func (redis *Redis) LoadZoneRecord(key string, zoneName string, conn redisCon.Conn) *record.Records {
	var (
		err error
		ttl int = -2
		val string
	)

	x, err := redis.LoadZoneRecord2("A", key, zoneName, conn)
	if err != nil {
		log.Errorf("LoadZoneRecord2: %s", err)
	} else {
		fmt.Println(x)
	}

	var label string
	if key == zoneName {
		label = "@"
	} else {
		label = key
	}

	err = conn.Send("MULTI")
	if err != nil {
		log.Errorf("redis: could start a Redis MULTI transaction: %s", err)
		return nil
	}
	err = conn.Send("HGET", redis.Key(zoneName), label)
	if err != nil {
		log.Errorf("redis: could not request a Redis HGET operation: %s", err)
		return nil
	}
	ttlKey := redis.TtlKey(label, zoneName)
	err = conn.Send("TTL", ttlKey)
	if err != nil {
		log.Errorf("redis: could not request a Redis TTL operation: %s", err)
		return nil
	}
	values, err := redisCon.Values(conn.Do("EXEC"))
	if err != nil {
		log.Errorf("redis: error in EXEC: %s", err)
		return nil
	}
	values, err = redisCon.Scan(values, &val, &ttl)
	if err != nil {
		log.Errorf("redis: error retrieving values: %s", err)
		return nil
	}

	r := new(record.Records)
	err = json.Unmarshal([]byte(val), r)
	if err != nil {
		log.Errorf("redis: error %s parsing %s", err, val)
		return nil
	}

	if ttl == -2 {
		// Insert a special TTL key in Redis for the DNS record
		r.Ttl = redis.ttl(zoneName, r.Ttl)
		_, err := conn.Do("SET", ttlKey, r.Ttl, "EX", r.Ttl)
		if err != nil {
			log.Errorf("redis: error %s when configuring TTL for %s.%s", err, label, zoneName)
		}
	} else {
		// Yield the remaining TTL for the DNS record according to Redis
		r.Ttl = uint32(ttl)
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

// Key2 returns the given key with prefix
func (redis *Redis) Key2(zoneName string) string {
	return redis.keyPrefix + zoneName
}

// TtlKey returns the given key used to keep track of decreasing TTLs
func (redis *Redis) TtlKey(location, zoneName string) string {
	return redis.keyPrefix + dns.Fqdn(zoneName) + redis.ttlSuffix + "/" + location
}

// TtlKey2 returns the given key used to keep track of decreasing TTLs
func (redis *Redis) TtlKey2(recordType, recordName, zoneName string) string {
	return redis.keyPrefix + zoneName + ":ttl:" + recordName + "/" + recordType
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
