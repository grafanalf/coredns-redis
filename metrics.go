package redis

import (
	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// the number of times that Redis Dial() has been called successfully
	redisDialCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "redis",
		Name:      "dial_total",
		Help:      "Counter of calls to Redis Dial().",
	}, []string{"server", "zone"})

	// the number of times that Redis Dial() has been called with error
	redisDialErrorCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "redis",
		Name:      "dial_error_total",
		Help:      "Counter of failed calls to Redis Dial().",
	}, []string{"server", "zone"})

	// the number of times that Redis Dial() has been called successfully
	redisDialSuccessCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "redis",
		Name:      "dial_success_total",
		Help:      "Counter of successful calls to Redis Dial().",
	}, []string{"server", "zone"})

	// reloadInfo is record the hash value during reload.
	redisPoolStats = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "redis",
		Name:      "redis_pool_stats",
		Help:      "A metric with Redis Pool statistics.",
	}, []string{"server", "zone", "stat"})
)
