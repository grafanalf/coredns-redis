package record

import "net"

// SOA RDATA (https://tools.ietf.org/html/rfc1035#section-3.3.13)
type SOA struct {
	Ttl     int    `json:"ttl"`
	MName   string `json:"mname"`
	RName   string `json:"rname"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	MinTtl  uint32 `json:"min_ttl"`
}

type A struct {
	Ttl int    `json:"ttl"`
	Ip  net.IP `json:"ip"`
}
type AAAA struct {
	Ttl int    `json:"ttl"`
	Ip  net.IP `json:"ip"`
}

type TXT struct {
	Ttl  int    `json:"ttl"`
	Text string `json:"text"`
}

type CNAME struct {
	Ttl  int    `json:"ttl"`
	Host string `json:"host"`
}

// NS RDATA (https://tools.ietf.org/html/rfc1035#section-3.3.11)
type NS struct {
	Ttl  int    `json:"ttl"`
	Host string `json:"host"`
}

// MX RDATA (https://tools.ietf.org/html/rfc1035#section-3.3.9)
type MX struct {
	Ttl        int    `json:"ttl"`
	Host       string `json:"host"`
	Preference uint16 `json:"preference"`
}

// SRV RDATA (https://tools.ietf.org/html/rfc2782)
type SRV struct {
	Ttl      int    `json:"ttl"`
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Port     uint16 `json:"port"`
	Target   string `json:"target"`
}
type PTR struct {
	Ttl  int    `json:"ttl"`
	Name string `json:"name"`
}

type CAA struct {
	Ttl   int    `json:"ttl"`
	Flag  uint8  `json:"flag"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}
