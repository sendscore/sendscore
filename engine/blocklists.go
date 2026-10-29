package engine

import "net"

// Blocklist is a DNS domain blocklist: a domain is looked up as
// <domain>.<Zone>, and an A record in the list's range means it is listed.
type Blocklist struct {
	Name string
	Zone string
	// TestDomain is always listed. Looking it up first proves the list is
	// answering rather than silently returning nothing.
	TestDomain string
	kind       string
}

// SpamhausDQS is Spamhaus DBL through Data Query Service, which allows
// commercial use with a key (free for low volume, paid beyond it).
func SpamhausDQS(key string) Blocklist {
	return Blocklist{Name: "Spamhaus DBL", Zone: key + ".dbl.dq.spamhaus.net", TestDomain: "dbltest.com", kind: "spamhaus"}
}

// SpamhausPublic is the free public DBL zone. Spamhaus allows it for
// non-commercial use only, and refuses queries through large public resolvers.
func SpamhausPublic() Blocklist {
	return Blocklist{Name: "Spamhaus DBL", Zone: "dbl.spamhaus.org", TestDomain: "dbltest.com", kind: "spamhaus"}
}

// SURBLPublic is the free public SURBL zone, for non-commercial use only.
func SURBLPublic() Blocklist {
	return Blocklist{Name: "SURBL", Zone: "multi.surbl.org", TestDomain: "test.surbl.org", kind: "surbl"}
}

// SURBLZone is a SURBL data feed zone, for subscribers.
func SURBLZone(zone string) Blocklist {
	return Blocklist{Name: "SURBL", Zone: zone, TestDomain: "test.surbl.org", kind: "surbl"}
}

// listed reports whether an answer means the domain is on the list.
func (b Blocklist) listed(ip net.IP) bool {
	v := ip.To4()
	if v == nil || v[0] != 127 {
		return false
	}
	switch b.kind {
	case "spamhaus":
		// 127.0.1.2 to 127.0.1.99 are listings; 127.0.1.255 means the
		// query was an IP address, which is an error, not a listing.
		return v[1] == 0 && v[2] == 1 && v[3] >= 2 && v[3] <= 99
	case "surbl":
		return v[1] == 0 && v[2] == 0 && v[3] > 1
	}
	return false
}

// refusal explains an answer that means the list would not answer.
func (b Blocklist) refusal(ip net.IP) string {
	v := ip.To4()
	if v == nil || v[0] != 127 {
		return ""
	}
	switch b.kind {
	case "spamhaus":
		if v[1] == 255 && v[2] == 255 {
			switch v[3] {
			case 252:
				return "the query was malformed"
			case 254:
				return "Spamhaus refuses queries through large public DNS resolvers"
			case 255:
				return "too many queries"
			}
			return "Spamhaus refused the query"
		}
		if v[1] == 0 && v[2] == 1 && v[3] == 255 {
			return "IP addresses cannot be looked up"
		}
	case "surbl":
		if v[1] == 0 && v[2] == 0 && v[3] == 1 {
			return "SURBL refused the query"
		}
	}
	return ""
}
