/// @file sim/ns3/link_profiles.cc
/// What a DNS lookup costs over different access links, with and without
/// encryption: a small ns-3 simulation of EVALUATION.md S1's question.
///
/// For each link profile (EVALUATION.md §3.4: LAN, 4G, rural broadband,
/// a lossy link, GEO satellite) a client and a server sit at the two ends of
/// one point-to-point link with that profile's delay, bandwidth and packet
/// loss. The client makes the same DNS-sized lookups three ways:
///
///   udp        one query datagram, one answer; retried after 1 s if lost
///   tls-fresh  a new TCP connection, a TLS 1.3 handshake (ClientHello, then
///              the server's ~2 KB flight with its certificate), then the
///              query: what DoT or DoH costs on a new connection
///   tls-reused the query alone on an open connection: DoT/DoH steady state
///
/// The server here is a stand-in that answers with realistic sizes; it is not
/// DNSentinel. This isolates what the link does. Running the real resolver
/// behind ns-3 links (emulation mode) is the full S1 in EVALUATION.md §5.
///
/// Build and run with sim/ns3/run.sh. Output: one CSV row per lookup, and a
/// summary table (median and 95th percentile per profile and transport).

#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <functional>
#include <iostream>
#include <string>
#include <vector>

using namespace ns3;

namespace {

// ─── What goes over the wire ────────────────────────────────────────────────
// Sizes of a lookup for www.example.com with EDNS, and of a TLS 1.3 handshake
// with a short certificate chain. Over TCP every message carries DNS's 2-byte
// length prefix; TLS adds ~22 bytes of record overhead.
constexpr uint32_t kUdpQuery     = 45;
constexpr uint32_t kUdpAnswer    = 100;
constexpr uint32_t kClientHello  = 250;
constexpr uint32_t kServerFlight = 2000;  // ServerHello ... Certificate ... Finished
constexpr uint32_t kTlsQuery     = 45 + 22 + 60;  // the query, plus the client's Finished on a new connection
constexpr uint32_t kTlsAnswer    = 100 + 22;

constexpr uint16_t kDnsPort = 53;
constexpr uint16_t kDotPort = 853;

constexpr double kUdpRetry   = 1.0;   // seconds before a stub resends a lost query
constexpr int    kUdpTries   = 3;
constexpr double kGiveUpTime = 30.0;  // a lookup still unanswered after this has failed

enum MessageType : uint8_t { kHello = 1, kFlight = 2, kQuery = 3, kAnswer = 4 };

struct Profile {
    std::string name;
    double      rtt_ms;
    double      loss;  // fraction of packets lost, each direction
    std::string rate;
};

struct Lookup {
    std::string profile, transport;
    int         index    = 0;
    double      ms       = 0;
    int         attempts = 1;
    bool        ok       = false;
};

/// A message: [length: 2][type: 1][id: 2][padding], `size` bytes in all.
Ptr<Packet> message(MessageType type, uint16_t id, uint32_t size) {
    std::vector<uint8_t> bytes(std::max<uint32_t>(size, 5), 0);
    const uint32_t       length = static_cast<uint32_t>(bytes.size()) - 2;
    bytes[0] = static_cast<uint8_t>(length >> 8);
    bytes[1] = static_cast<uint8_t>(length);
    bytes[2] = type;
    bytes[3] = static_cast<uint8_t>(id >> 8);
    bytes[4] = static_cast<uint8_t>(id);
    return Create<Packet>(bytes.data(), static_cast<uint32_t>(bytes.size()));
}

/// Splits a TCP byte stream back into messages.
struct Framer {
    std::vector<uint8_t> buffer;

    void add(Ptr<Packet> packet) {
        const size_t at = buffer.size();
        buffer.resize(at + packet->GetSize());
        packet->CopyData(buffer.data() + at, packet->GetSize());
    }
    /// The next whole message's (type, id), if one has arrived.
    bool next(MessageType& type, uint16_t& id) {
        if (buffer.size() < 2) return false;
        const size_t length = (size_t{buffer[0]} << 8) | buffer[1];
        if (buffer.size() < 2 + length) return false;
        type = static_cast<MessageType>(buffer[2]);
        id   = static_cast<uint16_t>((buffer[3] << 8) | buffer[4]);
        buffer.erase(buffer.begin(), buffer.begin() + static_cast<ptrdiff_t>(2 + length));
        return true;
    }
};

uint16_t id_of(Ptr<Packet> packet) {
    uint8_t head[5] = {};
    packet->CopyData(head, std::min<uint32_t>(packet->GetSize(), 5));
    return static_cast<uint16_t>((head[3] << 8) | head[4]);
}

// ─── The server: answers UDP queries, and TLS-shaped exchanges over TCP ────

class Server {
public:
    explicit Server(Ptr<Node> node) {
        udp_ = Socket::CreateSocket(node, UdpSocketFactory::GetTypeId());
        udp_->Bind(InetSocketAddress(Ipv4Address::GetAny(), kDnsPort));
        udp_->SetRecvCallback(MakeCallback(&Server::on_udp, this));

        tcp_ = Socket::CreateSocket(node, TcpSocketFactory::GetTypeId());
        tcp_->Bind(InetSocketAddress(Ipv4Address::GetAny(), kDotPort));
        tcp_->Listen();
        tcp_->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                MakeCallback(&Server::on_accept, this));
    }

private:
    void on_udp(Ptr<Socket> socket) {
        Address from;
        while (Ptr<Packet> packet = socket->RecvFrom(from)) {
            socket->SendTo(message(kAnswer, id_of(packet), kUdpAnswer), 0, from);
        }
    }

    void on_accept(Ptr<Socket> socket, const Address&) {
        framers_.emplace_back();
        const size_t slot = framers_.size() - 1;
        socket->SetRecvCallback(MakeBoundCallback(&Server::on_tcp, this, slot));
    }

    static void on_tcp(Server* self, size_t slot, Ptr<Socket> socket) {
        Framer& framer = self->framers_[slot];
        while (Ptr<Packet> packet = socket->Recv()) framer.add(packet);
        MessageType type;
        uint16_t    id;
        while (framer.next(type, id)) {
            if (type == kHello) socket->Send(message(kFlight, id, kServerFlight));
            if (type == kQuery) socket->Send(message(kAnswer, id, kTlsAnswer));
        }
    }

    Ptr<Socket>         udp_, tcp_;
    std::vector<Framer> framers_;  // one per accepted connection
};

// ─── The client: makes `count` lookups one after another ───────────────────

class Client {
public:
    Client(Ptr<Node> node, Ipv4Address server, std::string profile, std::vector<Lookup>& results)
        : node_(node), server_(server), profile_(std::move(profile)), results_(results) {}

    /// Lookups of one transport, starting at `start`, `gap` apart; then `next`.
    void run(const std::string& transport, int count, Time start, Time gap, std::function<void()> next) {
        transport_ = transport;
        remaining_ = count;
        index_     = 0;
        gap_       = gap;
        next_      = std::move(next);
        if (transport_ == "tls-reused") {
            Simulator::Schedule(start, &Client::open_reused, this);
        } else {
            Simulator::Schedule(start, &Client::begin, this);
        }
    }

private:
    // One lookup.
    void begin() {
        started_  = Simulator::Now();
        attempts_ = 1;
        waiting_  = true;
        ++query_id_;
        give_up_ = Simulator::Schedule(Seconds(kGiveUpTime), &Client::finish, this, false);
        if (transport_ == "udp") {
            if (!udp_) {
                udp_ = Socket::CreateSocket(node_, UdpSocketFactory::GetTypeId());
                udp_->Bind();
                udp_->Connect(InetSocketAddress(server_, kDnsPort));
                udp_->SetRecvCallback(MakeCallback(&Client::on_udp, this));
            }
            send_udp();
        } else if (transport_ == "tls-fresh") {
            framer_ = Framer{};
            tcp_    = Socket::CreateSocket(node_, TcpSocketFactory::GetTypeId());
            tcp_->Bind();
            tcp_->SetConnectCallback(MakeCallback(&Client::on_connected, this),
                                     MakeCallback(&Client::on_connect_failed, this));
            tcp_->SetRecvCallback(MakeCallback(&Client::on_tcp, this));
            tcp_->Connect(InetSocketAddress(server_, kDotPort));
        } else {  // tls-reused: the connection is already up
            tcp_->Send(message(kQuery, query_id_, kTlsQuery));
        }
    }

    void finish(bool ok) {
        if (!waiting_) return;  // a late duplicate answer, or the give-up timer after one
        waiting_ = false;
        Simulator::Cancel(give_up_);
        Simulator::Cancel(retry_);
        Lookup lookup;
        lookup.profile   = profile_;
        lookup.transport = transport_;
        lookup.index     = index_;
        lookup.ms        = (Simulator::Now() - started_).GetSeconds() * 1000.0;
        lookup.attempts  = attempts_;
        lookup.ok        = ok;
        results_.push_back(lookup);
        if (transport_ == "tls-fresh") close_tcp();
        ++index_;
        if (--remaining_ > 0) {
            Simulator::Schedule(gap_, &Client::begin, this);
        } else {
            if (transport_ == "tls-reused") close_tcp();
            Simulator::Schedule(gap_, next_);
        }
    }

    void close_tcp() {
        if (!tcp_) return;
        tcp_->SetRecvCallback(MakeNullCallback<void, Ptr<Socket>>());
        tcp_->Close();
        tcp_ = nullptr;
    }

    // UDP: resend after kUdpRetry, at most kUdpTries times in all.
    void send_udp() {
        udp_->Send(message(kQuery, query_id_, kUdpQuery));
        retry_ = Simulator::Schedule(Seconds(kUdpRetry), &Client::udp_timeout, this);
    }
    void udp_timeout() {
        if (attempts_ >= kUdpTries) {
            finish(false);
            return;
        }
        ++attempts_;
        send_udp();
    }
    void on_udp(Ptr<Socket> socket) {
        while (Ptr<Packet> packet = socket->Recv()) {
            if (id_of(packet) == query_id_) finish(true);
        }
    }

    // TLS-shaped exchanges over TCP.
    void on_connected(Ptr<Socket> socket) {
        if (transport_ == "tls-reused" && !reused_ready_) {
            socket->Send(message(kHello, 0, kClientHello));  // the one handshake, not timed
            return;
        }
        socket->Send(message(kHello, query_id_, kClientHello));
    }
    void on_connect_failed(Ptr<Socket>) {
        if (transport_ == "tls-reused" && !reused_ready_) {  // the untimed setup: try again
            Simulator::Schedule(Seconds(1), &Client::open_reused, this);
            return;
        }
        finish(false);
    }
    void on_tcp(Ptr<Socket> socket) {
        while (Ptr<Packet> packet = socket->Recv()) framer_.add(packet);
        MessageType type;
        uint16_t    id;
        while (framer_.next(type, id)) {
            if (type == kFlight && transport_ == "tls-reused" && !reused_ready_) {
                reused_ready_ = true;  // handshake done: start the timed lookups
                Simulator::Schedule(gap_, &Client::begin, this);
            } else if (type == kFlight) {
                socket->Send(message(kQuery, query_id_, kTlsQuery));
            } else if (type == kAnswer && id == query_id_) {
                finish(true);
            }
        }
    }
    void open_reused() {
        reused_ready_ = false;
        framer_       = Framer{};
        tcp_          = Socket::CreateSocket(node_, TcpSocketFactory::GetTypeId());
        tcp_->Bind();
        tcp_->SetConnectCallback(MakeCallback(&Client::on_connected, this),
                                 MakeCallback(&Client::on_connect_failed, this));
        tcp_->SetRecvCallback(MakeCallback(&Client::on_tcp, this));
        tcp_->Connect(InetSocketAddress(server_, kDotPort));
    }

    Ptr<Node>            node_;
    Ipv4Address          server_;
    std::string          profile_, transport_;
    std::vector<Lookup>& results_;
    std::function<void()> next_;
    Ptr<Socket>          udp_, tcp_;
    Framer               framer_;
    Time                 started_, gap_;
    EventId              give_up_, retry_;
    int                  remaining_ = 0, index_ = 0, attempts_ = 1;
    uint16_t             query_id_  = 0;
    bool                 waiting_ = false;  // a lookup is under way
    bool                 reused_ready_ = false;
};

/// One profile: build the link, run the three transports in turn.
void simulate(const Profile& p, int count, std::vector<Lookup>& results) {
    NodeContainer nodes;
    nodes.Create(2);  // 0: client, 1: server

    PointToPointHelper link;
    link.SetDeviceAttribute("DataRate", StringValue(p.rate));
    link.SetChannelAttribute("Delay", TimeValue(MicroSeconds(static_cast<int64_t>(p.rtt_ms * 500))));  // one way
    NetDeviceContainer devices = link.Install(nodes);
    for (uint32_t i = 0; i < devices.GetN(); ++i) {
        auto loss = CreateObject<RateErrorModel>();
        loss->SetAttribute("ErrorRate", DoubleValue(p.loss));
        loss->SetAttribute("ErrorUnit", EnumValue(RateErrorModel::ERROR_UNIT_PACKET));
        devices.Get(i)->SetAttribute("ReceiveErrorModel", PointerValue(loss));
    }

    InternetStackHelper internet;
    internet.Install(nodes);
    Ipv4AddressHelper addresses;
    addresses.SetBase("10.0.0.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = addresses.Assign(devices);

    Server server(nodes.Get(1));
    Client client(nodes.Get(0), interfaces.GetAddress(1), p.name, results);
    const Time gap = MilliSeconds(200);
    client.run("udp", count, Seconds(1), gap, [&] {
        client.run("tls-fresh", count, Seconds(0), gap, [&] {
            client.run("tls-reused", count, Seconds(0), gap, [] { Simulator::Stop(); });
        });
    });
    Simulator::Run();
    Simulator::Destroy();
}

double percentile(std::vector<double> values, double q) {
    if (values.empty()) return 0;
    std::sort(values.begin(), values.end());
    const size_t at = std::min(values.size() - 1, static_cast<size_t>(q * static_cast<double>(values.size() - 1) + 0.5));
    return values[at];
}

}  // namespace

int main(int argc, char** argv) {
    int         count = 100;
    uint32_t    run   = 1;
    std::string out   = "link_profiles.csv";
    CommandLine cmd(__FILE__);
    cmd.AddValue("count", "lookups per profile and transport", count);
    cmd.AddValue("run", "random stream number, for independent repetitions", run);
    cmd.AddValue("out", "CSV file to write", out);
    cmd.Parse(argc, argv);
    RngSeedManager::SetSeed(1);
    RngSeedManager::SetRun(run);
    // TCP closer to Linux than ns-3's defaults: full-size segments, a 200 ms
    // minimum retransmission timeout, a 1 s SYN timeout. And no timestamp
    // option: with small requests and answers whose ACKs ride on the next
    // message after idle gaps, ns-3's timestamp-based RTT samples include the
    // idle time, and its retransmission timeout grew to 30-70 s on a 60 ms
    // link, so one lost packet stalled a reused connection for over half a
    // minute. Without timestamps it samples RTT the classic way (Karn).
    Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(1448));
    Config::SetDefault("ns3::TcpSocketBase::MinRto", TimeValue(MilliSeconds(200)));
    Config::SetDefault("ns3::TcpSocket::ConnTimeout", TimeValue(Seconds(1)));
    Config::SetDefault("ns3::TcpSocketBase::Timestamp", BooleanValue(false));

    // EVALUATION.md §3.4 (the Wi-Fi profile needs the 802.11 model; not in this small version).
    const std::vector<Profile> profiles = {
        {"LAN", 1, 0.0, "1Gbps"},           {"4G", 60, 0.01, "20Mbps"},  {"Rural", 80, 0.005, "4Mbps"},
        {"Lossy", 50, 0.05, "10Mbps"},      {"Satellite", 600, 0.005, "10Mbps"},
    };

    std::vector<Lookup> results;
    for (const auto& p : profiles) simulate(p, count, results);

    std::ofstream csv(out);
    csv << "profile,transport,index,latency_ms,attempts,ok\n";
    for (const auto& r : results) {
        csv << r.profile << ',' << r.transport << ',' << r.index << ',' << r.ms << ',' << r.attempts << ','
            << (r.ok ? 1 : 0) << '\n';
    }

    std::printf("%-10s %-11s %10s %10s %8s\n", "profile", "transport", "median ms", "p95 ms", "failed");
    for (const auto& p : profiles) {
        for (const std::string transport : {"udp", "tls-reused", "tls-fresh"}) {
            std::vector<double> ms;
            int                 failed = 0;
            for (const auto& r : results) {
                if (r.profile != p.name || r.transport != transport) continue;
                if (r.ok) {
                    ms.push_back(r.ms);
                } else {
                    ++failed;
                }
            }
            std::printf("%-10s %-11s %10.1f %10.1f %8d\n", p.name.c_str(), transport.c_str(), percentile(ms, 0.5),
                        percentile(ms, 0.95), failed);
        }
    }
    std::cout << "wrote " << out << "\n";
    return 0;
}
