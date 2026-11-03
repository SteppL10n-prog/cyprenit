// Cyprenit Engine v1.0.0-Beta — user-space loader (cilium/ebpf).
//
// On a real kernel (>=5.8, BTF, root/CAP_BPF):
//  1. tls_probe.bpf.o is loaded; the socket_filter program is attached to an
//     AF_PACKET capture socket via SO_ATTACH_BPF (observation only — always
//     returns TC_ACT_OK).
//  2. The BPF_MAP_TYPE_RINGBUF reader is wired into the async pipeline via
//     AttachRing; kernel telemetry flows to user space without blocking
//     (Requirement #3).
//
// In environments where eBPF cannot run (containers/CI, kernel 4.19), the
// --dry-run mode synthesises ClientHello ABI frames and proves the same
// async path end to end.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/SteppL10n-prog/cyprenit/internal/abi"
	"github.com/SteppL10n-prog/cyprenit/internal/metrics"
	"github.com/SteppL10n-prog/cyprenit/internal/parser"
	"github.com/SteppL10n-prog/cyprenit/internal/ring"
	"github.com/SteppL10n-prog/cyprenit/internal/testdata"
)

type config struct {
	dryRun      bool
	workers     int
	queueDepth  int
	ifindex     int
	reportEvery time.Duration
	reportFile  string
	duration    time.Duration
	subnets     []string
	ports       []int
}

// subnetFilter and portFilter are consulted by every capture source
// (live eBPF ring, pcap replay, dry-run feed) before Submit().
var (
	subnetFilter []*net.IPNet
	portFilter   map[int]bool
)

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitInts(s string) []int {
	var out []int
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			log.Fatalf("invalid port %q: %v", p, err)
		}
		out = append(out, n)
	}
	return out
}

// matchTarget reports whether an event with the given src/dst IP and
// destination port should be observed. Empty filters = allow all.
func matchTarget(saddr, daddr string, dport uint16) bool {
	if len(portFilter) > 0 && !portFilter[int(dport)] {
		return false
	}
	if len(subnetFilter) == 0 {
		return true
	}
	for _, ipStr := range [2]string{saddr, daddr} {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		for _, n := range subnetFilter {
			if n.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// metricsFilter is set once at startup (before any producer goroutine
// starts) and consulted by the pcap replay and dry-run feed paths. The
// live eBPF path uses it via AttachRingFiltered instead.
var metricsFilter func(*abi.Event) bool

// eventFilter builds the ring-reader predicate from the compiled
// subnet/port filters. Returns nil when no filter is configured so the
// hot path pays zero cost (attach unfiltered).
func eventFilter() func(*abi.Event) bool {
	if len(subnetFilter) == 0 && len(portFilter) == 0 {
		return nil
	}
	return func(e *abi.Event) bool {
		s := net.IP(e.Saddr[:]).String()
		d := net.IP(e.Daddr[:]).String()
		return matchTarget(s, d, e.Dport)
	}
}

func compileFilters(cfg *config) error {
	for _, c := range cfg.subnets {
		if strings.Contains(c, "/") {
			_, n, err := net.ParseCIDR(c)
			if err != nil {
				return fmt.Errorf("invalid CIDR %q: %w", c, err)
			}
			subnetFilter = append(subnetFilter, n)
			continue
		}
		ip := net.ParseIP(c)
		if ip == nil {
			return fmt.Errorf("invalid IP/CIDR %q", c)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		subnetFilter = append(subnetFilter, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	if len(cfg.ports) > 0 {
		portFilter = make(map[int]bool, len(cfg.ports))
		for _, p := range cfg.ports {
			if p < 1 || p > 65535 {
				return fmt.Errorf("invalid port %d", p)
			}
			portFilter[p] = true
		}
	}
	return nil
}

func main() {
	cfg := config{}
	flag.BoolVar(&cfg.dryRun, "dry-run", false, "run end-to-end with synthetic telemetry without loading eBPF")
	flag.IntVar(&cfg.workers, "workers", 4, "number of decode workers")
	flag.IntVar(&cfg.queueDepth, "queue-depth", 4096, "bounded queue depth (full => counted drop)")
	flag.IntVar(&cfg.ifindex, "ifindex", 0, "interface ifindex to observe (0 = all interfaces)")
	flag.DurationVar(&cfg.reportEvery, "report", 10*time.Second, "risk-map report interval")
	flag.StringVar(&cfg.reportFile, "out", "", "path of the Cyprenit compliance (DORA/ISO 27001) Markdown audit report written at shutdown")
	flag.DurationVar(&cfg.duration, "duration", 0, "0 = run forever; >0 shut down gracefully after this duration, as on SIGTERM")
	capPorts := flag.String("capture-ports", "", "observe only these TCP ports (comma-separated: 443,8443; empty = all)")
	capCIDRs := flag.String("capture-nets", "", "observe only these IPs/CIDRs — matches when SOURCE or DESTINATION hits (comma-separated: 10.0.4.0/24,192.168.1.50; empty = all)")
	pcap := flag.String("pcap", "", "replay a pcap file through the kernel-filter twin instead of live eBPF (trial mode)")
	flag.Parse()

	cfg.subnets = splitList(*capCIDRs)
	cfg.ports = splitInts(*capPorts)
	if err := compileFilters(&cfg); err != nil {
		log.Fatalf("filter error: %v", err)
	}
	if len(cfg.subnets) > 0 || len(cfg.ports) > 0 {
		log.Printf("capture filters active: nets=%v ports=%v", cfg.subnets, cfg.ports)
		metricsFilter = eventFilter()
	}

	riskMap := metrics.NewMap()
	sink := func(rec *parser.ParsedRecord) {
		// Value copy: pipeline releases the pooled record right after the
		// sink returns, so the map must never retain pool-owned memory.
		riskMap.Observe(metrics.View(rec))
	}

	pipeline := ring.NewPipeline(cfg.workers, cfg.queueDepth, sink)

	switch {
	case *pcap != "":
		if err := replayPCAP(pipeline, *pcap); err != nil {
			log.Printf("pcap replay: %v", err)
			_ = pipeline.Close(2 * time.Second)
			os.Exit(4)
		}
	case !cfg.dryRun:
		cleanup, err := attachEBPF(pipeline, cfg.ifindex)
		if err != nil {
			log.Printf("failed to load eBPF (%v) — no kernel support in this environment; use --dry-run or --pcap", err)
			_ = pipeline.Close(2 * time.Second)
			os.Exit(3)
		}
		defer cleanup()
	default:
		go syntheticFeed(pipeline)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	tick := time.NewTicker(cfg.reportEvery)
	defer tick.Stop()

	var deadline <-chan time.Time
	if cfg.duration > 0 {
		dt := time.NewTimer(cfg.duration)
		defer dt.Stop()
		deadline = dt.C
	}

	for {
		select {
		case <-tick.C:
			report(riskMap, pipeline)
		case <-deadline:
			log.Printf("duration elapsed — graceful shutdown")
			shutdown(riskMap, pipeline, cfg.reportFile)
			return
		case s := <-sig:
			log.Printf("shutdown signal: %v", s)
			shutdown(riskMap, pipeline, cfg.reportFile)
			return
		}
	}
}

// shutdown: final report + bounded Close + pool verification + audit report.
func shutdown(riskMap *metrics.Map, pipeline *ring.Pipeline, reportFile string) {
	report(riskMap, pipeline)
	// Bounded Close: never wait indefinitely on a wedged consumer.
	if err := pipeline.Close(5 * time.Second); err != nil {
		log.Printf("warning: %v", err)
	}
	inUse, peak, gets, puts := parser.Stats()
	fmt.Printf("shutdown: pool in-use=%d peak=%d gets=%d puts=%d (in-use MUST be 0)\n",
		inUse, peak, gets, puts)
	if reportFile != "" {
		rows := riskMap.Snapshot()
		flows := make([]metrics.ReportRow, 0, len(rows))
		for _, r := range rows {
			flows = append(flows, metrics.ReportRow{
				Network:        r.Key.Daddr,
				Port:           int(r.Key.Dport),
				AlgorithmClass: dominantClass(r),
				RiskScore:      r.Census.MaxRisk,
				PriorityLabel:  r.Label,
				VolumeTPS:      r.VolumeTPS,
			})
		}
		if err := metrics.GenerateStandardReport(reportFile, flows); err != nil {
			log.Printf("failed to write audit report: %v", err)
			return
		}
		fmt.Printf("audit report written: %s\n", reportFile)
	}
}

func dominantClass(r metrics.FlowRow) string {
	type kv struct {
		n int64
		s string
	}
	cands := []kv{{r.Census.RSAKX, "RSA-KX"}, {r.Census.ECC, "ECC"},
		{r.Census.Hybrid, "HYBRID(X25519+ML-KEM)"}, {r.Census.PurePQC, "PURE-PQC"},
		{r.Census.Unknown, "UNKNOWN"}}
	best := cands[0]
	for _, c := range cands[1:] {
		if c.n > best.n {
			best = c
		}
	}
	return best.s
}

// attachEBPF loads the pre-compiled object, wires the kernel ring buffer to
// the async pipeline and attaches the observe-only socket filter.
func attachEBPF(p *ring.Pipeline, ifindex int) (func(), error) {
	// Build first: clang -O2 -g -target bpf -c ebpf/tls_probe.bpf.c -o ebpf/tls_probe.bpf.o
	spec, err := ebpf.LoadCollectionSpec("ebpf/tls_probe.bpf.o")
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}
	col, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("collection: %w", err)
	}

	prog := col.Programs["tls_socket_filter"]
	if prog == nil {
		col.Close()
		return nil, fmt.Errorf("program tls_socket_filter not found")
	}
	rb, err := ringbuf.NewReader(col.Maps["tls_events"])
	if err != nil {
		col.Close()
		return nil, fmt.Errorf("ring reader: %w", err)
	}
	if err := p.AttachRingFiltered(rb, eventFilter()); err != nil {
		rb.Close()
		col.Close()
		return nil, err
	}

	// AF_PACKET capture socket + SO_ATTACH_BPF (the filter only observes).
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		rb.Close()
		col.Close()
		return nil, fmt.Errorf("af_packet socket: %w", err)
	}
	sll := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifindex, // 0 => all interfaces
	}
	if err := unix.Bind(fd, &sll); err != nil {
		unix.Close(fd)
		rb.Close()
		col.Close()
		return nil, fmt.Errorf("bind af_packet: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, prog.FD()); err != nil {
		unix.Close(fd)
		rb.Close()
		col.Close()
		return nil, fmt.Errorf("SO_ATTACH_BPF: %w", err)
	}

	log.Printf("eBPF loaded: socket_filter fd=%d ifindex=%d; ring buffer async consumer active", fd, ifindex)
	cleanup := func() {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DETACH_BPF, 0) // best effort
		unix.Close(fd)
		_ = rb.Close() // wakes the kernel reader immediately
		col.Close()
	}
	return cleanup, nil
}

func report(m *metrics.Map, p *ring.Pipeline) {
	sub, over, parsed, _, panics, emitted := p.Snapshot()
	fmt.Printf("== Cyprenit PQC Risk Map == submitted=%d overflow=%d parsed=%d emitted=%d panics=%d\n",
		sub, over, parsed, emitted, panics)
	rows := m.Snapshot()
	for i, row := range rows {
		if i >= 10 {
			fmt.Printf("  ... +%d flow daha\n", len(rows)-10)
			break
		}
		c := row.Census
		fmt.Printf("  [%-8s] %s:%d rsa_kx=%d ecc=%d hybrid=%d pqc=%d unknown=%d\n",
			row.Label, row.Key.Daddr, row.Key.Dport, c.RSAKX, c.ECC, c.Hybrid, c.PurePQC, c.Unknown)
	}
}

// syntheticFrame mirrors exactly what the kernel socket_filter would write
// into the ring buffer: cyprenit_evt header fields + 5-byte-record-header-
// stripped ClientHello payload (kernel truncates to PayloadMax).
func syntheticFrameAt(v []byte, i int, alt bool) []byte {
	buf := make([]byte, abi.EventSize)
	dst := [4]byte{10, 0, 4, 250} // DMZ subnet 10.0.4.0/24
	if alt {
		dst = [4]byte{192, 168, 7, 20} // core subnet 192.168.7.0/24
	}
	e := &abi.Event{
		TimestampNS: uint64(time.Now().UnixNano()),
		PidTgid:     uint32(os.Getpid()) << 16,
		Saddr:       [4]byte{10, 0, 0, 5},
		Daddr:       dst,
		Sport:       41234, Dport: 443,
		Direction: abi.DirEgress, HSType: abi.HSClientHello,
		TLSVersion: 0x0303, Cookie: uint32(i),
		Payload: v[5:], // kernel strips the 5-byte record header
	}
	if err := e.Encode(buf); err != nil {
		return nil
	}
	return buf
}

// syntheticFeed builds ABI frames exactly like the kernel probe would
// (header-stripped payload into cyprenit_evt) and pumps them through Submit().
func syntheticFeed(p *ring.Pipeline) {
	vectors := [][]byte{
		testdata.RSAClientHello,
		testdata.ECCClientHello,
		testdata.PQCClientHello,
		testdata.HybridClientHello,
	}
	i := 0
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for range t.C {
		v := vectors[i%len(vectors)]
		i++
		buf := syntheticFrameAt(v, i, i%2 == 0)
		if buf == nil {
			log.Printf("synthetic encode failed")
			continue
		}
		if metricsFilter != nil {
			ev, err := abi.Decode(buf)
			if err != nil || !metricsFilter(ev) {
				continue // non-target synthetic flow: never reaches Submit
			}
		}
		if err := p.Submit(buf); err != nil {
			log.Printf("synthetic submit: %v", err)
		}
	}
}

// replayPCAP reads a pcap file (classic libpcap format, DLT_EN10MB or
// DLT_RAW), re-injects every TCP packet that carries a TLS ClientHello
// through the same kernel-side filtering logic the eBPF program runs
// (IPv4/TCP parse + 0x16 handshake detection + 92-byte truncation), and
// submits the resulting cyprenit_evt frames. This lets you trial the FULL
// pipeline on production traffic captures WITHOUT a live eBPF-capable
// kernel — byte-for-byte the same code path as the real ring reader.
func replayPCAP(p *ring.Pipeline, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read pcap: %w", err)
	}
	if len(data) < 24 {
		return fmt.Errorf("pcap too short")
	}
	magic := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	var little bool
	switch magic {
	case 0xa1b2c3d4:
	case 0xd4c3b2a1:
		little = true
	default:
		return fmt.Errorf("not a classic pcap (magic=%#x)", magic)
	}
	u32 := func(b []byte) uint32 {
		if little {
			return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
		}
		return uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
	}
	network := int(u32(data[20:24]))
	off := 24
	sent, matched, skipped := 0, 0, 0
	for off+16 <= len(data) {
		incl := int(u32(data[off+8 : off+12]))
		off += 16
		if incl < 0 || off+incl > len(data) {
			return fmt.Errorf("pcap truncated at record %d", sent)
		}
		pkt := data[off : off+incl]
		off += incl
		sent++
		ev, ok := extractTLSEvent(pkt, network)
		if !ok {
			continue
		}
		if metricsFilter != nil && !metricsFilter(ev) {
			skipped++
			continue
		}
		matched++
		buf := make([]byte, abi.EventSize)
		if err := ev.Encode(buf); err != nil {
			continue
		}
		if err := p.Submit(buf); err != nil {
			return err
		}
	}
	fmt.Printf("pcap replay: %d packets read, %d TLS handshakes -> Submit, %d skipped by filter (%s)\n", sent, matched, skipped, path)
	return nil
}

// extractTLSEvent is the user-space twin of tls_socket_filter in
// ebpf/tls_probe.bpf.c: ETH/IP/TCP walk, payload scan for content_type 0x16,
// cyprenit_evt fill with 92-byte truncation.
func extractTLSEvent(pkt []byte, network int) (*abi.Event, bool) {
	var l3 []byte
	switch network {
	case 1: // DLT_RAW: IPv4 directly
		l3 = pkt
	case 12, 101, 113: // DLT_EN10MB / LINUX_SLL / LINUX_SLL2 (skip link header)
		if network == 12 {
			if len(pkt) < 14 {
				return nil, false
			}
			l3 = pkt[14:]
		} else {
			hdr := 16
			if network == 113 {
				hdr = 20
			}
			if len(pkt) < hdr {
				return nil, false
			}
			l3 = pkt[hdr:]
		}
	default:
		return nil, false
	}
	if len(l3) < 20 || l3[0]>>4 != 4 {
		return nil, false
	}
	ihl := int(l3[0]&0x0f) * 4
	total := int(l3[2])<<8 | int(l3[3])
	if ihl < 20 || total < ihl || len(l3) < total {
		return nil, false
	}
	if l3[9] != 6 { // IPPROTO_TCP
		return nil, false
	}
	tcp := l3[ihl:]
	if len(tcp) < 20 {
		return nil, false
	}
	doff := int(tcp[12]>>4) * 4
	payload := tcp[doff:]
	if len(payload) < 6 {
		return nil, false
	}
	if payload[0] != 0x16 { // not a TLS handshake record
		return nil, false
	}
	recLen := int(payload[3])<<8 | int(payload[4])
	body := payload[5:]
	if len(body) == 0 {
		return nil, false
	}
	if recLen > len(body) {
		recLen = len(body)
	}
	trunc := recLen
	if trunc > abi.PayloadMax {
		trunc = abi.PayloadMax
	}
	var saddr, daddr [4]byte
	copy(saddr[:], l3[12:16])
	copy(daddr[:], l3[16:20])
	hsType := body[0]
	tlsVer := uint16(0x0303)
	if recLen >= 6 {
		tlsVer = uint16(body[1])<<8 | uint16(body[2])
	}
	return &abi.Event{
		TimestampNS: uint64(time.Now().UnixNano()),
		PidTgid:     0,
		Saddr:       saddr, Daddr: daddr,
		Sport:      uint16(tcp[0])<<8 | uint16(tcp[1]),
		Dport:      uint16(tcp[2])<<8 | uint16(tcp[3]),
		Direction:  abi.DirIngress,
		HSType:     hsType,
		TLSVersion: tlsVer,
		RecordLen:  uint16(recLen),
		Cookie:     uint32(len(payload)),
		Payload:    body[:trunc],
	}, true
}

// htons converts a constant to network byte order for sockaddr fields.
func htons(v uint16) uint16 { return v<<8 | v>>8 }
