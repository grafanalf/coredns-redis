package record

// Records holds the location records for a zone
type Records struct {
	Ttl int `json:"ttl",omitempty`
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
