//go:build linux

// Linux raw-socket backend: AF_PACKET SOCK_RAW bound to the egress interface,
// reading captured frames from an mmap'd TPACKET_V2 RX ring (PACKET_RX_RING).
// Requires CAP_NET_RAW (run as root).

package main

import (
	"encoding/binary"
	"sync/atomic"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

func htons(v uint16) uint16 { return (v<<8)&0xff00 | v>>8 }

// RX-ring geometry. The kernel requires block_size to be a multiple of the page
// size and of frame_size, frame_size to be a multiple of TPACKET_ALIGNMENT, and
// frame_nr == (block_size/frame_size)*block_nr. Captured frames here are only
// the small control packets the BPF filter lets through (SYN / pure ACK), so a
// 2 KiB frame is ample; the total ring is 512 KiB and replaces both the old
// per-packet recvfrom path and the SO_RCVBUF socket buffer as where frames land.
const (
	tpFrameSize = 2048
	tpBlockSize = 1 << 15 // 32 KiB (8 pages)
	tpBlockNr   = 16
	tpFrameNr   = (tpBlockSize / tpFrameSize) * tpBlockNr // 256 frames
)

var (
	rxRing []byte // mmap'd ring shared with the kernel
	rxIdx  int    // next frame slot to inspect (frames are consumed in order)
)

// sniffFilter builds a classic-BPF program that the kernel applies to the
// AF_PACKET socket so only the packets sniffLoop actually acts on reach
// userspace: IPv4 TCP segments to/from connectIP that carry no payload (SYNs
// and pure ACKs). This drops every relayed data frame in the kernel, which is
// the bulk of the traffic on a busy forwarder. It is a safe superset of what
// sniffLoop inspects — every branch there already requires plen == 0 — and the
// precise localIP/connectIP matching still happens in Go.
//
// Equivalent tcpdump:
//
//	tcp and host <connectIP> and
//	  (ip[2:2] - ((ip[0]&0x0f)<<2) - ((tcp[12]&0xf0)>>2)) == 0
//
// Offsets are into the full Ethernet frame (14-byte L2 header included).
func sniffFilter(connIP []byte) ([]unix.SockFilter, error) {
	raw, err := bpf.Assemble(sniffFilterInsns(binary.BigEndian.Uint32(connIP)))
	if err != nil {
		return nil, err
	}
	filter := make([]unix.SockFilter, len(raw))
	for i, r := range raw {
		filter[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	return filter, nil
}

// sniffFilterInsns is the instruction list for sniffFilter, split out so it can
// be exercised by the pure-Go bpf.VM in tests.
func sniffFilterInsns(conn uint32) []bpf.Instruction {
	return []bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2},                            // A = ethertype
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0x0800, SkipTrue: 18}, // not IPv4 -> drop
		bpf.LoadAbsolute{Off: 23, Size: 1},                            // A = IP protocol
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 6, SkipTrue: 16},      // not TCP -> drop
		bpf.LoadAbsolute{Off: 26, Size: 4},                            // A = src IP
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: conn, SkipTrue: 2},       // src==connIP -> hostOK
		bpf.LoadAbsolute{Off: 30, Size: 4},                            // A = dst IP
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: conn, SkipTrue: 12},   // dst!=connIP -> drop
		bpf.LoadMemShift{Off: 14},                                     // X = IP header length (bytes)
		bpf.LoadAbsolute{Off: 16, Size: 2},                            // A = IP total length
		bpf.ALUOpX{Op: bpf.ALUOpSub},                                  // A = total - ihl
		bpf.StoreScratch{Src: bpf.RegA, N: 0},                         // M[0] = A
		bpf.LoadIndirect{Off: 26, Size: 1},                            // A = tcp[12] (data-offset byte)
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xf0},                //
		bpf.ALUOpConstant{Op: bpf.ALUOpShiftRight, Val: 2},            // A = TCP header length (bytes)
		bpf.TAX{},                            // X = TCP header length
		bpf.LoadScratch{Dst: bpf.RegA, N: 0}, // A = total - ihl
		bpf.ALUOpX{Op: bpf.ALUOpSub},         // A = TCP payload length
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0, SkipTrue: 1}, // payload != 0 -> drop
		bpf.RetConstant{Val: 262144},                            // accept (whole frame)
		bpf.RetConstant{Val: 0},                                 // drop
	}
}

func openRaw() error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}

	// TPACKET_V2 must be selected before the ring is requested.
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VERSION, unix.TPACKET_V2); err != nil {
		unix.Close(fd)
		return err
	}

	// Attach the kernel-side filter before the ring exists so filtered-out
	// frames never consume a ring slot or reach the single sniffLoop goroutine.
	filter, err := sniffFilter(connectIP)
	if err != nil {
		unix.Close(fd)
		return err
	}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER,
		&unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}); err != nil {
		unix.Close(fd)
		return err
	}

	// Request the mmap'd RX ring (kernel writes captured frames here directly).
	req := &unix.TpacketReq{
		Block_size: tpBlockSize,
		Block_nr:   tpBlockNr,
		Frame_size: tpFrameSize,
		Frame_nr:   tpFrameNr,
	}
	if err := unix.SetsockoptTpacketReq(fd, unix.SOL_PACKET, unix.PACKET_RX_RING, req); err != nil {
		unix.Close(fd)
		return err
	}

	ring, err := unix.Mmap(fd, 0, tpBlockSize*tpBlockNr,
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Close(fd)
		return err
	}

	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifaceIdx,
	}); err != nil {
		_ = unix.Munmap(ring)
		unix.Close(fd)
		return err
	}

	rawFd = fd
	rxRing = ring
	rxIdx = 0
	return nil
}

// recvFrame returns the next captured Ethernet frame, copied into buf. It walks
// the RX ring in order: each slot's status flips to TP_STATUS_USER when the
// kernel has filled it, and we flip it back to TP_STATUS_KERNEL once consumed.
// When the next slot isn't ready it blocks in poll() until the kernel fills it,
// so a burst of control packets is drained with one wakeup instead of one
// recvfrom syscall per packet.
func recvFrame(buf []byte) (int, error) {
	for {
		off := rxIdx * tpFrameSize
		hdr := (*unix.Tpacket2Hdr)(unsafe.Pointer(&rxRing[off]))

		if atomic.LoadUint32(&hdr.Status)&unix.TP_STATUS_USER == 0 {
			pfd := []unix.PollFd{{Fd: int32(rawFd), Events: unix.POLLIN | unix.POLLERR}}
			if _, err := unix.Poll(pfd, -1); err != nil {
				if err == unix.EINTR {
					continue
				}
				return 0, err
			}
			continue
		}

		if atomic.LoadUint32(&hdr.Status)&unix.TP_STATUS_LOSING != 0 {
			logDebugf("[sniff] RX ring reports drops (TP_STATUS_LOSING)")
		}

		n := int(hdr.Len)
		macOff := off + int(hdr.Mac)
		copied := copy(buf, rxRing[macOff:macOff+n])

		// Hand the slot back to the kernel. The store-release pairs with the
		// kernel's barrier before it set TP_STATUS_USER on this slot.
		atomic.StoreUint32(&hdr.Status, unix.TP_STATUS_KERNEL)

		rxIdx++
		if rxIdx >= tpFrameNr {
			rxIdx = 0
		}
		return copied, nil
	}
}

func sendFrame(frame []byte) error {
	sll := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_IP),
		Ifindex:  ifaceIdx,
		Halen:    6,
	}
	copy(sll.Addr[:6], frame[0:6])
	return unix.Sendto(rawFd, frame, 0, sll)
}
