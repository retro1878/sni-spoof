//go:build linux

package main

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/net/bpf"
)

// frame builds a minimal Ethernet+IPv4 frame for the given L4 protocol, src/dst
// IPs, optional TCP header (with the given data-offset words and flags) plus
// payload. It exercises the same offsets sniffFilterInsns computes.
func frame(proto byte, src, dst net.IP, tcpDataOffWords int, payload int) []byte {
	const eth = 14
	ihl := 20
	tcpHdr := tcpDataOffWords * 4
	ipTotal := ihl + tcpHdr + payload

	f := make([]byte, eth+ipTotal)
	binary.BigEndian.PutUint16(f[12:14], 0x0800) // IPv4 ethertype

	ip := f[eth:]
	ip[0] = 0x40 | byte(ihl/4) // version 4, IHL
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipTotal))
	ip[9] = proto
	copy(ip[12:16], src.To4())
	copy(ip[16:20], dst.To4())

	if proto == 6 {
		tcp := ip[ihl:]
		tcp[12] = byte(tcpDataOffWords << 4)
	}
	return f
}

func TestSniffFilterAcceptsOnlyZeroPayloadTCPToHost(t *testing.T) {
	conn := net.ParseIP("104.18.4.130")
	local := net.ParseIP("10.0.0.5")
	other := net.ParseIP("8.8.8.8")

	vm, err := bpf.NewVM(sniffFilterInsns(binary.BigEndian.Uint32(conn.To4())))
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}
	run := func(f []byte) bool {
		n, err := vm.Run(f)
		if err != nil {
			t.Fatalf("vm.Run: %v", err)
		}
		return n > 0
	}

	cases := []struct {
		name string
		f    []byte
		want bool
	}{
		{"outbound SYN (no payload)", frame(6, local, conn, 5, 0), true},
		{"outbound pure ACK", frame(6, local, conn, 5, 0), true},
		{"inbound pure ACK", frame(6, conn, local, 5, 0), true},
		{"pure ACK, TCP options (no payload)", frame(6, conn, local, 8, 0), true},
		{"outbound data packet", frame(6, local, conn, 5, 1400), false},
		{"inbound data packet", frame(6, conn, local, 5, 1400), false},
		{"TCP but unrelated host", frame(6, local, other, 5, 0), false},
		{"UDP to host", frame(17, local, conn, 5, 0), false},
	}
	for _, c := range cases {
		if got := run(c.f); got != c.want {
			t.Errorf("%s: filter pass = %v, want %v", c.name, got, c.want)
		}
	}
}
