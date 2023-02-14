package plugin

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	redisCon "github.com/gomodule/redigo/redis"
	redis "github.com/grafanalf/coredns-redis"
	"github.com/miekg/dns"
)

const name = "redis"

var log = clog.NewWithPlugin("redis")

type Plugin struct {
	Redis *redis.Redis
	Next  plugin.Handler

	loadZoneTicker *time.Ticker
	zones          []string
	lastRefresh    time.Time
	lock           sync.Mutex
}

func (p *Plugin) Name() string {
	return name
}

func (p *Plugin) Ready() bool {
	ok, err := p.Redis.Ping()
	if err != nil {
		log.Error(err)
	}
	return ok
}

func (p *Plugin) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{Req: r, W: w}
	qName := state.Name()
	qType := state.QType()

	if qName == "" || qType == dns.TypeNone {
		return plugin.NextOrFailure(qName, p.Next, ctx, w, r)
	}

	var conn redisCon.Conn
	defer func() {
		if conn == nil {
			return
		}
		_ = conn.Close()
	}()

	var zoneName string
	x := sort.SearchStrings(p.zones, qName)
	if x >= 0 && x < len(p.zones) && p.zones[x] == qName {
		zoneName = p.zones[x]
	} else {
		zoneName = plugin.Zones(p.zones).Matches(qName)
	}

	if zoneName == "" {
		log.Debugf("zone not found: %s", qName)
		p.checkCache()
		return plugin.NextOrFailure(qName, p.Next, ctx, w, r)
	}

	conn = p.Redis.Pool.Get()
	zone := p.Redis.LoadZoneC(zoneName, false, conn)
	if zone == nil {
		log.Errorf("unable to load zone: %s", zoneName)
		return p.Redis.ErrorResponse(state, zoneName, dns.RcodeServerFailure, nil)
	}

	location := p.Redis.FindLocation(qName, zone.Name)
	answers := make([]dns.RR, 0, 0)
	extras := make([]dns.RR, 0, 10)
	zoneRecords := p.Redis.LoadZoneRecord(location, zone.Name, conn)
	if zoneRecords == nil {
		return p.Redis.ErrorResponse(state, zoneName, dns.RcodeServerFailure, nil)
	}

	switch qType {
	case dns.TypeSOA:
		answers, extras = p.Redis.SOA(zone.Name, zoneRecords)
	case dns.TypeA:
		answers, extras = p.Redis.A(qName, zoneRecords)
	case dns.TypeAAAA:
		answers, extras = p.Redis.AAAA(qName, zoneRecords)
	case dns.TypeCNAME:
		answers, extras = p.Redis.CNAME(qName, zoneRecords)
	case dns.TypeTXT:
		answers, extras = p.Redis.TXT(qName, zoneRecords)
	case dns.TypeNS:
		answers, extras = p.Redis.NS(qName, zone.Name, zoneRecords, p.zones, conn)
	case dns.TypeMX:
		answers, extras = p.Redis.MX(qName, zone.Name, zoneRecords, p.zones, conn)
	case dns.TypeSRV:
		answers, extras = p.Redis.SRV(qName, zone.Name, zoneRecords, p.zones, conn)
	case dns.TypePTR:
		answers, extras = p.Redis.PTR(qName, zone.Name, zoneRecords, p.zones, conn)
	case dns.TypeCAA:
		answers, extras = p.Redis.CAA(qName, zoneRecords)

	default:
		return p.Redis.ErrorResponse(state, zoneName, dns.RcodeNotImplemented, nil)
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative, m.RecursionAvailable, m.Compress = true, false, true
	m.Answer = append(m.Answer, answers...)
	m.Extra = append(m.Extra, extras...)
	state.SizeAndDo(m)
	m = state.Scrub(m)
	_ = w.WriteMsg(m)
	return dns.RcodeSuccess, nil
}

func (p *Plugin) startZoneNameCache() {

	if err := p.loadCache(); err != nil {
		log.Fatal("unable to load zones to cache", err)
	} else {
		log.Info("zone name cache loaded")
	}
	go func() {
		for {
			select {
			case <-p.loadZoneTicker.C:
				if err := p.loadCache(); err != nil {
					log.Error("unable to load zones to cache", err)
					return
				} else {
					log.Infof("zone name cache refreshed (%v)", time.Now())
				}
			}
		}
	}()
}

func (p *Plugin) loadCache() error {
	z, err := p.Redis.LoadAllZoneNames()
	if err != nil {
		return err
	}
	sort.Strings(z)
	p.lock.Lock()
	p.zones = z
	p.lastRefresh = time.Now()
	p.lock.Unlock()
	return nil
}

func (p *Plugin) checkCache() {
	if time.Now().Sub(p.lastRefresh).Seconds() > float64(p.Redis.DefaultTtl*2) {
		p.startZoneNameCache()
	}
}
