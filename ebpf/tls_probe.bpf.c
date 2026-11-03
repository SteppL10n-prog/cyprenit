/* Cyprenit v1.0.0-Beta — Layer 4: Passive TLS Handshake Discovery (eBPF, kernel space)
 *
 * Non-invasive design rules:
 *   1. The socket_filter/SKB path is OBSERVATION-ONLY; it always returns
 *      TC_ACT_OK and never DROPs or REDIRECTs packets → zero network
 *      traffic disruption.
 *   2. Telemetry transport via BPF_MAP_TYPE_RINGBUF is asynchronous and
 *      NON-BLOCKING: when the ring is full, bpf_ringbuf_reserve() returns
 *      NULL → the event is recorded in the drop counter and the datapath
 *      continues; the kernel packet path is NEVER stalled (this closes the
 *      entire deadlock class at the producer).
 *      bpf_ringbuf_submit(..., BPF_RB_NO_WAKEUP) does not synchronously
 *      wake user space; the polling Go reader drains it every 50 ms
 *      (asynchronous consumption).
 *   3. The struct cyprenit_evt ABI MUST match internal/abi/abi.go exactly
 *      (TEST-04 golden vectors pin this contract in CI).
 *
 * Build (on a real machine):
 *   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
 *         -I/usr/include -c tls_probe.bpf.c -o tls_probe.bpf.o
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h> /* TC_ACT_OK */
#include <linux/in.h>       /* IPPROTO_TCP */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define CYPRENIT_EVENT_SIZE 128
#define CYPRENIT_PAYLOAD_MAX 92

/* skb->data meta access for socket_filter programs (kernel uapi defines the
 * full struct only under __BPF_API__; redeclare the fields we touch). */
struct cyprenit_skb {
	__u32 len;
	__u32 pkt_len;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;
	/* >= kernel 5.1: access to the ingress flag via field offset 17+... */
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 remote_port;
	__u32 local_port;
	__u32 data_meta;
	__u32 flow_dissector;
	__u8  from_tunnel;   /* == ingress indication on egress paths */
};

/* --- ABI: MUST match internal/abi/abi.go ------------------------------- */
struct cyprenit_evt {
	__u64 timestamp_ns;   /* off  0 */
	__u32 pid_tgid;       /* off  8 */
	__u32 saddr;          /* off 12 (IPv4, network order as seen on wire) */
	__u32 daddr;          /* off 16 */
	__u16 sport;          /* off 20 */
	__u16 dport;          /* off 22 */
	__u8  direction;      /* off 24 0=egress 1=ingress */
	__u8  hs_type;        /* off 25 TLS HandshakeType */
	__u16 tls_version;    /* off 26 */
	__u16 record_len;     /* off 28 */
	__u16 pad0;           /* off 30 */
	__u32 cookie;         /* off 32 flow correlation id */
	__u8  payload[CYPRENIT_PAYLOAD_MAX]; /* off 36..128 */
};

/* Ring buffer: kernel -> user-space async transport (Requirement #3) */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); /* 1 MiB: ~8192 event, bounded memory */
} tls_events SEC(".maps");

/* Per-CPU drop counter: overflow must be MEASURED, never blocking */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u64));
	__uint(max_entries, 4);
} cyprenit_counters SEC(".maps");

#define CNT_RING_FULL 0
#define CNT_TLS_SEEN  1
#define CNT_PARSE_ERR 2

static __always_inline void bump_cnt(__u32 idx)
{
	__u64 *c = bpf_map_lookup_elem(&cyprenit_counters, &idx);
	if (c)
		(*c)++;
}

/* The reserve+commit form: ringbuf output is non-blocking by contract;
 * failure => counted drop. Called from the filter below. */
static __always_inline void emit_event(struct __sk_buff *skb,
				       struct iphdr *iph, struct tcphdr *tcph,
				       __u8 *payload, __u32 plen, __u8 hs_type)
{
	struct cyprenit_evt *e = bpf_ringbuf_reserve(&tls_events,
						   CYPRENIT_EVENT_SIZE, 0);
	if (!e) {                 /* RING FULL: drop, count, NEVER stall */
		bump_cnt(CNT_RING_FULL);
		return;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid_tgid = bpf_get_current_pid_tgid();
	e->saddr = iph->saddr;
	e->daddr = iph->daddr;
	e->sport = tcph->source;
	e->dport = tcph->dest;
	/* socket_filter context: ingress indication read via redeclared
	 * layout (offset-stable across supported 5.x/6.x kernels). */
	struct cyprenit_skb *q = (void *)skb;
	e->direction = q->ingress_ifindex != 0 ? 1 : 0;
	e->hs_type = hs_type;
	e->tls_version = (payload[1] << 8) | payload[2];

	__u32 n = plen > 5 + CYPRENIT_PAYLOAD_MAX ? CYPRENIT_PAYLOAD_MAX
						: plen - 5;
	e->record_len = n;
	bpf_probe_read_kernel(e->payload, n & (CYPRENIT_PAYLOAD_MAX - 1), payload + 5);
	bpf_ringbuf_submit(e, BPF_RB_NO_WAKEUP); /* async: no scheduler IPI */
}

/* Minimal Ethernet+IPv4+TCP walker with full bounds checks. */
SEC("socket/version")
int tls_socket_filter(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK; /* observe-only: never touch the packet */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return TC_ACT_OK;
	if (iph->protocol != IPPROTO_TCP)
		return TC_ACT_OK;

	int l3 = iph->ihl * 4;
	if (l3 < 20 || (void *)iph + l3 > data_end)
		return TC_ACT_OK;
	struct tcphdr *tcph = (void *)iph + l3;
	if ((void *)(tcph + 1) > data_end)
		return TC_ACT_OK;

	__u16 doff = tcph->doff * 4;
	if (doff < 20 || (void *)tcph + doff > data_end)
		return TC_ACT_OK;

	__u8 *payload = (void *)tcph + doff;
	__u32 plen = (__u32)(data_end - (void *)payload);
	if (plen < 6)
		return TC_ACT_OK;

	/* TLS record heuristic: content_type==0x16(handshake), ver 0x0301..0x0304 */
	if (payload[0] != 0x16)
		return TC_ACT_OK;
	__u16 tls_ver = (payload[1] << 8) | payload[2];
	if (tls_ver < 0x0301 || tls_ver > 0x0304)
		return TC_ACT_OK;
	bump_cnt(CNT_TLS_SEEN);

	/* Kernel skips the 5-byte record header; hs_type = first handshake byte */
	__u8 hs_type = payload[5];
	emit_event(skb, iph, tcph, payload, plen, hs_type);
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
