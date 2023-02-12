package plugin

import (
	"errors"
	"fmt"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/grafanalf/coredns-redis"
	"strconv"
	"time"
)

func init() {
	fmt.Println("init redis")
	caddy.RegisterPlugin("redis", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	fmt.Println("setup redis")
	r, err := redisParse(c)
	if err != nil {
		fmt.Printf("setup redis failed: %w\n", err)
		return err
	}

	if ok, err := r.Ping(); err != nil || !ok {
		return plugin.Error("redis", err)
	} else if ok {
		log.Infof("ping to redis ok")
	}

	p := &Plugin{
		Redis:          r,
		loadZoneTicker: time.NewTicker(time.Duration(r.DefaultTtl) * time.Second),
	}
	p.startZoneNameCache()

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		p.Next = next
		return p
	})

	return nil
}

func redisParse(c *caddy.Controller) (*redis.Redis, error) {

	fmt.Println("redis: begin redisParse")
	if c.Next() {
		fmt.Printf("redis: c.Val() = %s\n", c.Val())
	}
	return nil, errors.New("no configuration found")

	r := redis.New()

	for c.Next() {
		if c.NextBlock() {
			for {
				fmt.Printf("redis: processing cmd '%s'\n", c.Val())
				switch c.Val() {
				case "address":
					if !c.NextArg() {
						fmt.Println("missing address parameter")
						return redis.New(), c.ArgErr()
					}
					fmt.Printf("setting Redis address to: '%s'\n", c.Val())
					r.SetAddress(c.Val())
				case "username":
					if !c.NextArg() {
						return redis.New(), c.ArgErr()
					}
					r.SetUsername(c.Val())
				case "password":
					if !c.NextArg() {
						return redis.New(), c.ArgErr()
					}
					r.SetPassword(c.Val())
				case "prefix":
					if !c.NextArg() {
						return redis.New(), c.ArgErr()
					}
					r.SetKeyPrefix(c.Val())
				case "suffix":
					if !c.NextArg() {
						return redis.New(), c.ArgErr()
					}
					r.SetKeySuffix(c.Val())
				case "connect_timeout":
					if !c.NextArg() {
						return redis.New(), c.ArgErr()
					}
					t, err := strconv.Atoi(c.Val())
					if err == nil {
						r.SetConnectTimeout(t)
					}
				case "read_timeout":
					if !c.NextArg() {
						return redis.New(), c.ArgErr()
					}
					t, err := strconv.Atoi(c.Val())
					if err != nil {
						r.SetReadTimeout(t)
					}
				case "ttl":
					if !c.NextArg() {
						return redis.New(), c.ArgErr()
					}
					t, err := strconv.Atoi(c.Val())
					if err != nil {
						r.SetDefaultTtl(redis.DefaultTtl)
					} else {
						r.SetDefaultTtl(t)
					}
				default:
					if c.Val() != "}" {
						return redis.New(), c.Errf("unknown property '%s'", c.Val())
					}
				}

				if !c.Next() {
					break
				}
			}
		}

		fmt.Println("trying to connect to Redis")
		err := r.Connect()
		return r, err
	}

	return nil, errors.New("no configuration found")
}
