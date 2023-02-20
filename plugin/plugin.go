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

	zones       []string
	lastRefresh time.Time
	lock        sync.Mutex
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
		log.Debugf("zone not loaded: %s", qName)
		p.checkCache()
		return plugin.NextOrFailure(qName, p.Next, ctx, w, r)
	}

	conn = p.Redis.Pool.Get()
	recordType := dns.TypeToString[qType]
	answers, extras, err := p.Redis.LoadZoneRecords(recordType, qName, zoneName, conn)
	if err != nil {
		log.Error(err)
		return p.Redis.ErrorResponse(state, zoneName, dns.RcodeServerFailure, nil)
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative, m.RecursionAvailable, m.Compress = true, false, true
	m.Answer = append(m.Answer, answers...)
	m.Extra = append(m.Extra, extras...)
	state.SizeAndDo(m)
	m = state.Scrub(m)
	err = w.WriteMsg(m)
	if err != nil {
		log.Error(err)
		return p.Redis.ErrorResponse(state, zoneName, dns.RcodeServerFailure, nil)
	}
	return dns.RcodeSuccess, nil
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
	if time.Since(p.lastRefresh) > time.Duration(redis.DefaultTtl*2*time.Second) {
		if err := p.loadCache(); err != nil {
			log.Fatalf("unable to cache zones: %s", err)
		}
	}
}
