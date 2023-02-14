package record

type Type string

// a record type tha implements the Equality interface
// can easily been checked for changes in the record
type Equality interface {
	// Equal returns 'false', if the values of both instances differ, otherwise 'true'
	Equal(r1 Equality) bool
}

type Record interface {
	// TTL returns the ttl for the record, if the second return value is 'false', no
	// ttl is set for the record and you should use the default min-ttl value
	TTL() (uint32, bool)
}

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
