package record

import "net"

// Records holds the location records for a zone
type Records struct {
	Ttl uint32 `json:"ttl"`

	// SOA record for the zone, mandatory but only allowed in '@'
	SOA   *SOA    `json:"SOA,omitempty"`
	A     []A     `json:"A,omitempty"`
	AAAA  []AAAA  `json:"AAAA,omitempty"`
	TXT   []TXT   `json:"TXT,omitempty"`
	CNAME []CNAME `json:"CNAME,omitempty"`
	NS    []NS    `json:"NS,omitempty"`
	MX    []MX    `json:"MX,omitempty"`
	SRV   []SRV   `json:"SRV,omitempty"`
	PTR   []PTR   `json:"PTR,omitempty"`
	CAA   []CAA   `json:"CAA,omitempty"`
}

// SOA RDATA (https://tools.ietf.org/html/rfc1035#section-3.3.13)
type SOA struct {
	MName   string `json:"mname"`
	RName   string `json:"rname"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	MinTtl  uint32 `json:"min_ttl"`
}

type A struct {
	Ip net.IP `json:"ip"`
}
type AAAA struct {
	Ip net.IP `json:"ip"`
}

type TXT struct {
	Text string `json:"text"`
}

type CNAME struct {
	Host string `json:"host"`
}

// NS RDATA (https://tools.ietf.org/html/rfc1035#section-3.3.11)
type NS struct {
	Host string `json:"host"`
}

// MX RDATA (https://tools.ietf.org/html/rfc1035#section-3.3.9)
type MX struct {
	Host       string `json:"host"`
	Preference uint16 `json:"preference"`
}

// SRV RDATA (https://tools.ietf.org/html/rfc2782)
type SRV struct {
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Port     uint16 `json:"port"`
	Target   string `json:"target"`
}
type PTR struct {
	Name string `json:"name"`
}

type CAA struct {
	Flag  uint8  `json:"flag"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}
