package redis

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/log"
)

func init() {
	plugin.Register("redis", setup)
}

func setup(c *caddy.Controller) error {
	r, err := redisParse(c)
	if err != nil {
		return err
	}

	ping, err := r.InitPool()
	if err != nil {
		return err
	}
	if !ping {
		return fmt.Errorf("Redis PING failed")
	}

	log.Infof("redis: Pool(\"%s\").MaxActive=%d", r.Zone, r.maxActive)
	log.Infof("redis: Pool(\"%s\").MaxIdle=%d", r.Zone, r.maxIdle)
	log.Infof("redis: Pool(\"%s\").IdleTimeout=%d", r.Zone, r.idleTimeout)

	p := &Plugin{Redis: r}
	go p.updateRedisPoolStats(10 * time.Second)
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		p.Next = next
		return p
	})

	return nil
}

func redisParse(c *caddy.Controller) (*Redis, error) {

	if c.Next() {
		if c.Val() != "redis" {
			return nil, c.ArgErr()
		}
		if !c.NextArg() {
			return nil, c.ArgErr()
		}

		log.Infof("redis: configuring Redis support for domain %s", c.Val())
		r := New(c.Val())
		if c.NextBlock() {
			for {
				switch c.Val() {
				case "address":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					r.SetAddress(c.Val())

				case "username":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					r.SetUsername(c.Val())
				case "password":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					r.SetPassword(c.Val())
				case "prefix":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					r.SetKeyPrefix(c.Val())
				case "connect_timeout":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					t, err := strconv.Atoi(c.Val())
					if err == nil {
						r.SetConnectTimeout(t)
					}
				case "read_timeout":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					t, err := strconv.Atoi(c.Val())
					if err != nil {
						r.SetReadTimeout(t)
					}
				case "idle_timeout":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					t, err := strconv.Atoi(c.Val())
					if err != nil {
						return nil, c.ArgErr()
					}
					r.SetIdleTimeOut(t)
				case "max_active":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					t, err := strconv.Atoi(c.Val())
					if err != nil {
						return nil, c.ArgErr()
					}
					r.SetMaxActive(t)
				case "max_idle":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					t, err := strconv.Atoi(c.Val())
					if err != nil {
						return nil, c.ArgErr()
					}
					r.SetMaxIdle(t)
				default:
					if c.Val() != "}" {
						return nil, c.Errf("unknown property '%s'", c.Val())
					}
				}

				if !c.Next() {
					break
				}
			}
		}

		return r, nil
	}

	return nil, errors.New("no configuration found")
}
