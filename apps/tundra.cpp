// tundra: the stack on a TAP (or TUN) device, with a few services to talk to from the Linux side.
//
//   ip tuntap add dev tap0 mode tap && ip addr add 10.0.0.1/24 dev tap0 && ip link set tap0 up
//   tundra --dev tap0 --ip 10.0.0.2/24
//
//   ping 10.0.0.2                                  ICMP echo
//   echo hi | nc -u -w1 10.0.0.2 7                 UDP echo
//   nc 10.0.0.2 7                                  TCP echo (9 discards)
//   curl -sD- http://10.0.0.2/bytes/1000000 -o f   N bytes, with their SHA-256 in X-SHA256
//   curl --data-binary @f http://10.0.0.2/sha256   the SHA-256 of what it received
#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>

#include "tundra/linux.hpp"
#include "tundra/pcap.hpp"
#include "tundra/sha256.hpp"
#include "tundra/stack.hpp"

using namespace tundra;

namespace {

std::atomic<bool> g_stop{false};
bool g_verbose = false;

void log(const char* fmt, auto... args) {
    if (g_verbose) std::fprintf(stderr, fmt, args...);
}

std::string peer(const TcpConnection& c) {
    return c.tuple().remote_ip.str() + ":" + std::to_string(c.tuple().remote_port);
}

// Sender pushes a buffer through a connection as the send window allows, then optionally closes.
struct Sender {
    std::weak_ptr<TcpConnection> conn;
    Buffer data;
    std::size_t off = 0;
    bool close_when_done = false;

    void pump() {
        auto c = conn.lock();
        if (!c) return;
        while (off < data.size()) {
            std::size_t n = c->send(Bytes(data).subspan(off));
            if (n == 0) return;  // on_writable calls us again
            off += n;
        }
        data.clear();
        off = 0;
        if (close_when_done) c->close();
    }
};

void serve_echo(Stack& s) {
    s.tcp_listen(7, [](std::shared_ptr<TcpConnection> c) {
        log("echo: %s connected\n", peer(*c).c_str());
        auto out = std::make_shared<Sender>();
        out->conn = c;
        c->on_data = [out](Bytes d) {
            out->data.insert(out->data.end(), d.begin(), d.end());
            out->pump();
        };
        c->on_writable = [out] { out->pump(); };
        c->on_peer_closed = [out] {
            out->close_when_done = true;
            out->pump();
        };
    });
}

void serve_discard(Stack& s) {
    s.tcp_listen(9, [](std::shared_ptr<TcpConnection> c) {
        auto bytes = std::make_shared<std::uint64_t>(0);
        std::weak_ptr<TcpConnection> w = c;
        c->on_data = [bytes](Bytes d) { *bytes += d.size(); };
        c->on_peer_closed = [w, bytes] {
            if (auto conn = w.lock()) {
                log("discard: %s sent %llu bytes\n", peer(*conn).c_str(), static_cast<unsigned long long>(*bytes));
                conn->close();
            }
        };
    });
}

// A deliberately small HTTP/1.0 server: one request per connection, then close.
struct Http : std::enable_shared_from_this<Http> {
    Stack& stack;
    std::weak_ptr<TcpConnection> conn;
    Sender out;
    std::string head;
    bool in_body = false;
    std::size_t content_length = 0, body_seen = 0;
    Sha256 body_hash;

    explicit Http(Stack& s) : stack(s) {}

    void respond(const std::string& status, const std::string& extra_headers, Buffer body) {
        std::string h = "HTTP/1.0 " + status + "\r\nContent-Length: " + std::to_string(body.size()) +
                        "\r\nConnection: close\r\n" + extra_headers + "\r\n";
        out.data.assign(reinterpret_cast<const std::byte*>(h.data()), reinterpret_cast<const std::byte*>(h.data()) + h.size());
        out.data.insert(out.data.end(), body.begin(), body.end());
        out.close_when_done = true;
        out.pump();
    }

    void text(const std::string& status, const std::string& s) {
        Buffer b(s.size());
        std::memcpy(b.data(), s.data(), s.size());
        respond(status, "Content-Type: text/plain\r\n", std::move(b));
    }

    void on_data(Bytes d) {
        if (in_body) return body(d);
        head.append(reinterpret_cast<const char*>(d.data()), d.size());
        auto end = head.find("\r\n\r\n");
        if (end == std::string::npos) {
            if (head.size() > 64 * 1024) text("431 Request Header Fields Too Large", "too large\n");
            return;
        }
        std::string rest = head.substr(end + 4);
        head.resize(end);
        auto sp1 = head.find(' '), sp2 = head.find(' ', sp1 + 1);
        if (sp1 == std::string::npos || sp2 == std::string::npos) return text("400 Bad Request", "bad request\n");
        std::string method = head.substr(0, sp1), path = head.substr(sp1 + 1, sp2 - sp1 - 1);
        log("http: %s %s\n", method.c_str(), path.c_str());
        if (method == "GET" && path == "/") return text("200 OK", index());
        if (method == "GET" && path.starts_with("/bytes/")) return bytes(path.substr(7));
        if (method == "POST" && path == "/sha256") {
            auto cl = head.find("Content-Length:");
            if (cl == std::string::npos) cl = head.find("content-length:");
            if (cl == std::string::npos) return text("411 Length Required", "need Content-Length\n");
            content_length = std::strtoull(head.c_str() + cl + 15, nullptr, 10);
            in_body = true;
            return body(std::as_bytes(std::span(rest.data(), rest.size())));
        }
        text("404 Not Found", "try /, /bytes/N or POST /sha256\n");
    }

    void body(Bytes d) {
        std::size_t take = std::min(d.size(), content_length - body_seen);
        body_hash.update(d.first(take));
        body_seen += take;
        if (body_seen == content_length) {
            in_body = false;
            text("200 OK", Sha256::hex(body_hash.finish()) + "\n");
        }
    }

    // bytes sends n deterministic pseudo-random bytes and their SHA-256 in X-SHA256.
    void bytes(const std::string& arg) {
        std::size_t n = std::strtoull(arg.c_str(), nullptr, 10);
        if (n > (std::size_t{512} << 20)) return text("413 Content Too Large", "at most 512 MiB\n");
        Buffer b(n);
        std::uint64_t x = 0x9e3779b97f4a7c15ULL ^ n;  // splitmix64
        for (std::size_t i = 0; i < n; i += 8) {
            std::uint64_t z = (x += 0x9e3779b97f4a7c15ULL);
            z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
            z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
            z ^= z >> 31;
            std::memcpy(b.data() + i, &z, std::min<std::size_t>(8, n - i));
        }
        Sha256 h;
        h.update(b);
        respond("200 OK", "Content-Type: application/octet-stream\r\nX-SHA256: " + Sha256::hex(h.finish()) + "\r\n",
                std::move(b));
    }

    std::string index() {
        const auto& st = stack.stats();
        char buf[512];
        std::snprintf(buf, sizeof buf,
                      "tundra: a user-space TCP/IP stack\n"
                      "frames in %llu, out %llu; dropped malformed %llu, not for us %llu\n"
                      "TCP connections opened %llu, resets sent %llu; ICMP echo replies %llu\n",
                      (unsigned long long)st.frames_in, (unsigned long long)st.frames_out,
                      (unsigned long long)st.dropped_malformed, (unsigned long long)st.dropped_not_for_us,
                      (unsigned long long)st.tcp_connections_opened, (unsigned long long)st.tcp_resets_out,
                      (unsigned long long)st.icmp_echo_replies);
        return buf;
    }
};

void serve_http(Stack& s) {
    s.tcp_listen(80, [&s](std::shared_ptr<TcpConnection> c) {
        auto h = std::make_shared<Http>(s);
        h->conn = c;
        h->out.conn = c;
        c->on_data = [h](Bytes d) { h->on_data(d); };
        c->on_writable = [h] { h->out.pump(); };
    });
}

void usage() {
    std::fprintf(stderr,
                 "usage: tundra --dev NAME --ip A.B.C.D/LEN [--tun] [--gw A.B.C.D] [--pcap FILE] [--loss P] [--verbose]\n");
    std::exit(2);
}

}  // namespace

int main(int argc, char** argv) {
    std::string dev_name, ip_arg, gw_arg, pcap_path;
    LinkType type = LinkType::ethernet;
    double loss = 0;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> std::string {
            if (i + 1 >= argc) usage();
            return argv[++i];
        };
        if (a == "--dev") dev_name = next();
        else if (a == "--ip") ip_arg = next();
        else if (a == "--gw") gw_arg = next();
        else if (a == "--pcap") pcap_path = next();
        else if (a == "--loss") loss = std::strtod(next().c_str(), nullptr);
        else if (a == "--tun") type = LinkType::ip;
        else if (a == "--verbose") g_verbose = true;
        else usage();
    }
    auto slash = ip_arg.find('/');
    if (dev_name.empty() || slash == std::string::npos) usage();
    StackConfig cfg;
    auto ip = Ipv4Addr::parse(ip_arg.substr(0, slash));
    if (!ip) usage();
    cfg.ip = *ip;
    cfg.prefix_len = static_cast<std::uint8_t>(std::stoi(ip_arg.substr(slash + 1)));
    if (!gw_arg.empty()) cfg.gateway = Ipv4Addr::parse(gw_arg);
    cfg.mac = MacAddr{{0x02, 't', 'u', 'n', 'd', 'r'}};
    cfg.seed = static_cast<std::uint64_t>(SteadyClock{}.now().time_since_epoch().count());

    auto dev = TapDevice::open(dev_name, type);
    if (!dev) {
        std::fprintf(stderr, "tundra: %s\n", dev.error().c_str());
        return 1;
    }
    if (loss > 0) (*dev)->set_loss(loss, cfg.seed);
    SteadyClock clock;
    Stack stack(**dev, clock, cfg);
    std::unique_ptr<PcapWriter> pcap;
    if (!pcap_path.empty()) {
        pcap = std::make_unique<PcapWriter>(pcap_path, type);
        stack.set_pcap(pcap.get());
    }
    serve_echo(stack);
    serve_discard(stack);
    serve_http(stack);
    stack.udp_bind(7, [&stack](Ipv4Addr src, std::uint16_t port, Bytes p) { stack.udp_send(7, src, port, p); });

    std::signal(SIGINT, [](int) { g_stop = true; });
    std::signal(SIGTERM, [](int) { g_stop = true; });
    std::fprintf(stderr, "tundra: %s %s/%d mac %s%s, serving echo :7 (tcp, udp), discard :9, http :80\n",
                 dev_name.c_str(), cfg.ip.str().c_str(), cfg.prefix_len, cfg.mac.str().c_str(),
                 loss > 0 ? (", losing " + std::to_string(loss * 100) + "% of frames each way").c_str() : "");
    auto r = run_event_loop(stack, **dev, g_stop);
    const auto& st = stack.stats();
    std::fprintf(stderr, "tundra: stopped; frames in %llu out %llu, TCP connections %llu, device drops %llu (full) %llu (loss)\n",
                 (unsigned long long)st.frames_in, (unsigned long long)st.frames_out,
                 (unsigned long long)st.tcp_connections_opened, (unsigned long long)(*dev)->dropped_full,
                 (unsigned long long)(*dev)->dropped_loss);
    if (!r) {
        std::fprintf(stderr, "tundra: %s\n", r.error().c_str());
        return 1;
    }
    return 0;
}
