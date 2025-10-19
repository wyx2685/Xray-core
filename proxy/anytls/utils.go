package anytls

import (
	"encoding/binary"

	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
)

// stream represents a single ANYTLS stream
type stream struct {
	link      *transport.Link
	isUDP     bool
	udpTarget *xnet.Destination
	isConnect bool // for UDP-over-TCP: true = fixed destination, false = per-packet destination
}

// parseUotAddr parses a UDP-over-TCP address format (ATYP 0/1/2)
// Returns UDPDestination for packet routing
func parseUotAddr(b []byte) (xnet.Destination, int, error) {
	if len(b) < 1 {
		return xnet.Destination{}, 0, errors.New("anytls: empty addr")
	}
	atyp := b[0]
	p := 1
	var addr xnet.Address
	switch atyp {
	case 0x00: // IPv4
		if len(b) < p+4+2 {
			return xnet.Destination{}, 0, errors.New("anytls: short ipv4 addr")
		}
		addr = xnet.IPAddress(b[p : p+4])
		p += 4
	case 0x01: // IPv6
		if len(b) < p+16+2 {
			return xnet.Destination{}, 0, errors.New("anytls: short ipv6 addr")
		}
		addr = xnet.IPAddress(b[p : p+16])
		p += 16
	case 0x02: // Domain
		if len(b) < p+1 {
			return xnet.Destination{}, 0, errors.New("anytls: short domain len")
		}
		l := int(b[p])
		p++
		if len(b) < p+l+2 {
			return xnet.Destination{}, 0, errors.New("anytls: short domain addr")
		}
		addr = xnet.DomainAddress(string(b[p : p+l]))
		p += l
	default:
		return xnet.Destination{}, 0, errors.New("anytls: bad uot atyp")
	}
	port := xnet.Port(binary.BigEndian.Uint16(b[p : p+2]))
	p += 2

	return xnet.UDPDestination(addr, port), p, nil
}

// parseSocksAddr parses a SOCKS address format (ATYP 1/3/4)
// Returns TCPDestination for compatibility with existing code
func parseSocksAddr(b []byte) (xnet.Destination, int, error) {
	if len(b) < 1 {
		return xnet.Destination{}, 0, errors.New("anytls: empty addr")
	}
	atyp := b[0]
	p := 1
	var addr xnet.Address
	switch atyp {
	case 1: // IPv4
		if len(b) < p+4+2 {
			return xnet.Destination{}, 0, errors.New("anytls: short ipv4 addr")
		}
		addr = xnet.IPAddress(b[p : p+4])
		p += 4
	case 3: // Domain
		if len(b) < p+1 {
			return xnet.Destination{}, 0, errors.New("anytls: short domain len")
		}
		l := int(b[p])
		p++
		if len(b) < p+l+2 {
			return xnet.Destination{}, 0, errors.New("anytls: short domain addr")
		}
		addr = xnet.DomainAddress(string(b[p : p+l]))
		p += l
	case 4: // IPv6
		if len(b) < p+16+2 {
			return xnet.Destination{}, 0, errors.New("anytls: short ipv6 addr")
		}
		addr = xnet.IPAddress(b[p : p+16])
		p += 16
	default:
		return xnet.Destination{}, 0, errors.New("anytls: bad atyp")
	}
	port := xnet.Port(binary.BigEndian.Uint16(b[p : p+2]))
	p += 2

	// Always return TCP destination
	// UDP-over-TCP v2 uses a special magic domain "sp.v2.udp-over-tcp.arpa"
	// The actual UDP target address is embedded in the subsequent data stream
	// following the UDP-over-TCP v2 protocol format
	return xnet.TCPDestination(addr, port), p, nil
}
