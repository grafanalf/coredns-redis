package redis

import (
	"context"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

const name = "redis"

type Plugin struct {
	Redis *Redis
	Next  plugin.Handler
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

	if !strings.HasSuffix(qName, p.Redis.Zone) {
		log.Debugf("unsupported zone for query %s", qName)
		return plugin.NextOrFailure(qName, p.Next, ctx, w, r)
	}

	conn := p.Redis.Pool.Get()
	if conn == nil {
		log.Fatal("could not get a Redis connection")
	}
	defer conn.Close()

	recordType := dns.TypeToString[qType]
	answers, extras, err := p.Redis.LoadZoneRecords(recordType, qName, conn)
	if err != nil {
		log.Error(err)
		return p.Redis.ErrorResponse(state, qName, dns.RcodeServerFailure, nil)
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
		return p.Redis.ErrorResponse(state, qName, dns.RcodeServerFailure, nil)
	}
	return dns.RcodeSuccess, nil
}

// Update statistics about Redis Pools periodically
func (p *Plugin) updateRedisPoolStats(period time.Duration) {
	t := time.NewTicker(period)
	for {
		<-t.C
		redisPoolStats.WithLabelValues(
			p.Redis.hostName,
			p.Redis.Zone, "ActiveCount",
		).Set(float64(p.Redis.Pool.Stats().ActiveCount))
		redisPoolStats.WithLabelValues(
			p.Redis.hostName,
			p.Redis.Zone,
			"IdleCount",
		).Set(float64(p.Redis.Pool.Stats().IdleCount))
		log.Debug("Updated Redis Pool Stats")
	}
}
