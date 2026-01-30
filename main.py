import sys
import time
import random
import re

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.sendrecv import sr1, send, sniff
from scapy.utils import rdpcap, wrpcap

REQ_LINE_RE = re.compile(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP/(\d\.\d)\r\n", re.I)
RESP_LINE_RE = re.compile(r"^HTTP/(\d\.\d)\s+(\d{3})\s+([^\r\n]*)\r\n", re.I)

XSS_PATTERNS = [
    re.compile(r"<\s*script\b", re.I),
    re.compile(r"\bon\w+\s*=", re.I),
    re.compile(r"javascript\s*:", re.I),
    re.compile(r"<\s*img\b[^>]*\bonerror\s*=", re.I),
    re.compile(r"document\.cookie", re.I),
    re.compile(r"alert\s*\(", re.I),
]

def usage():
    print(
        "Usage:\n"
        "  python script_HW2.py send <dest> [raw_request] [count]\n"
        "  python script_HW2.py sniff [--iface IFACE] [--host HOST] [--seconds N] [--limit N] [--out FILE]\n"
        "  python script_HW2.py analyze <pcap> [--only-xss]\n"
    )

def classify_http(payload: bytes):
    try:
        text = payload.decode("iso-8859-1", errors="ignore")
    except Exception:
        return None
    if REQ_LINE_RE.match(text):
        return "request"
    if RESP_LINE_RE.match(text):
        return "response"
    return None

def parse_http(payload: bytes):
    try:
        text = payload.decode("iso-8859-1", errors="replace")
    except Exception:
        return None, {}, b""
    if "\r\n\r\n" not in text:
        return None, {}, b""
    head, rest = text.split("\r\n\r\n", 1)
    lines = head.split("\r\n")
    if not lines:
        return None, {}, b""
    first = lines[0]
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return first, headers, rest.encode("iso-8859-1", errors="replace")

def xss_hits(s: str):
    hits = []
    for p in XSS_PATTERNS:
        if p.search(s):
            hits.append(p.pattern)
    return hits

def send_http(dest: str, raw_request: str, count: int):
    if not raw_request:
        raw_request = "GET / HTTP/1.1\r\nHost: {}\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\n\r\n".format(dest)

    counter = 0
    while counter < count:
        sport = random.randint(1025, 65500)
        seq0 = random.randint(0, 2**32 - 1)

        syn = IP(dst=dest) / TCP(sport=sport, dport=80, flags="S", seq=seq0)
        syn_ack = sr1(syn, timeout=5, verbose=False)
        if syn_ack is None or not syn_ack.haslayer(TCP):
            print(f"Нет ответа SYN-ACK от {dest}. Пропускаю итерацию.")
            continue

        ackn = syn_ack[TCP].seq + 1
        seqn = syn_ack[TCP].ack

        ack_packet = IP(dst=dest) / TCP(dport=80, sport=sport, seq=seqn, ack=ackn, flags="A")
        send(ack_packet, verbose=False)

        http_request = IP(dst=dest) / TCP(dport=80, sport=sport, seq=seqn, ack=ackn, flags="PA") / raw_request
        response = sr1(http_request, timeout=5, verbose=False)
        if response:
            print(response.summary())
        else:
            print("Нет ответа после отправки HTTP.")
        counter += 1

def sniff_http(iface=None, host=None, seconds=30, limit=0, out_pcap="traffic.pcap"):
    flt = "tcp port 80"
    if host:
        flt += f" and host {host}"
    pkts = []

    def cb(pkt):
        pkts.append(pkt)

    kwargs = dict(filter=flt, prn=cb, store=False)
    if iface:
        kwargs["iface"] = iface
    if seconds and seconds > 0:
        kwargs["timeout"] = int(seconds)
    if limit and limit > 0:
        kwargs["count"] = int(limit)

    sniff(**kwargs)
    if out_pcap:
        wrpcap(out_pcap, pkts)

def analyze_pcap(pcap_path: str, only_xss: bool):
    pkts = rdpcap(pcap_path)
    for pkt in pkts:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue
        payload = bytes(pkt[Raw].load)
        kind = classify_http(payload)
        if not kind:
            continue
        first, headers, body = parse_http(payload)
        if not first:
            continue

        try:
            body_text = body.decode("utf-8", errors="ignore")
        except Exception:
            body_text = ""

        hdr_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
        blob = (first + "\n" + hdr_text + "\n\n" + body_text).lower()
        hits = xss_hits(blob)

        if only_xss and not hits:
            continue

        ts = float(getattr(pkt, "time", time.time()))
        tstr = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)

        print(f"[{tstr}] {kind.upper()} {src}:{sport} -> {dst}:{dport} :: {first}")
        if hits:
            print("XSS:", ", ".join(sorted(set(hits))))

def parse_kv_args(argv):
    opts = {}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a.startswith("--"):
            key = a[2:]
            val = True
            if i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                val = argv[i + 1]
                i += 1
            opts[key] = val
        i += 1
    return opts

def main():
    if len(sys.argv) < 2:
        usage()
        sys.exit(1)

    cmd = sys.argv[1].lower()

    if cmd == "send":
        if len(sys.argv) < 3:
            usage()
            sys.exit(1)
        dest = sys.argv[2]
        raw_request = ""
        count = 10

        if len(sys.argv) >= 4:
            raw_request = sys.argv[3]
        if len(sys.argv) >= 5:
            try:
                count = int(sys.argv[4])
            except ValueError:
                print("Максимальное количество запросов должно быть числом!")
                sys.exit(1)

        send_http(dest, raw_request, count)
        return

    if cmd == "sniff":
        opts = parse_kv_args(sys.argv[2:])
        iface = opts.get("iface", None)
        host = opts.get("host", None)
        seconds = int(opts.get("seconds", 30))
        limit = int(opts.get("limit", 0))
        out_pcap = opts.get("out", "traffic.pcap")
        sniff_http(iface=iface, host=host, seconds=seconds, limit=limit, out_pcap=out_pcap)
        return

    if cmd == "analyze":
        if len(sys.argv) < 3:
            usage()
            sys.exit(1)
        pcap = sys.argv[2]
        only_xss = "--only-xss" in sys.argv[3:]
        analyze_pcap(pcap, only_xss)
        return

    usage()
    sys.exit(1)

if __name__ == "__main__":
    main()
