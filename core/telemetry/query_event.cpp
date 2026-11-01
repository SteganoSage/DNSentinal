/// @file telemetry/query_event.cpp

#include "dnsentinel/telemetry/query_event.h"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <cstdio>

namespace dnsentinel::telemetry {

std::string type_name(uint16_t qtype) {
    switch (qtype) {  // as ml/tunnel/pcap.py TYPES: the detector compares these spellings
    case 1: return "A";
    case 2: return "NS";
    case 5: return "CNAME";
    case 6: return "SOA";
    case 10: return "NULL";
    case 12: return "PTR";
    case 13: return "HINFO";
    case 15: return "MX";
    case 16: return "TXT";
    case 17: return "RP";
    case 24: return "SIG";
    case 25: return "KEY";
    case 28: return "AAAA";
    case 29: return "LOC";
    case 33: return "SRV";
    case 35: return "NAPTR";
    case 39: return "DNAME";
    case 43: return "DS";
    case 46: return "RRSIG";
    case 47: return "NSEC";
    case 48: return "DNSKEY";
    case 52: return "TLSA";
    case 64: return "SVCB";
    case 65: return "HTTPS";
    case 99: return "SPF";
    case 251: return "IXFR";
    case 252: return "AXFR";
    case 255: return "ANY";
    case 256: return "URI";
    case 257: return "CAA";
    default: return "TYPE" + std::to_string(qtype);
    }
}

std::string rcode_name(uint8_t rcode) {
    switch (rcode) {
    case 0: return "NOERROR";
    case 1: return "FORMERR";
    case 2: return "SERVFAIL";
    case 3: return "NXDOMAIN";
    case 4: return "NOTIMP";
    case 5: return "REFUSED";
    default: return "RCODE" + std::to_string(rcode);
    }
}

std::string_view action_name(Action action) {
    switch (action) {
    case Action::Answer: return "answer";
    case Action::Block: return "block";
    case Action::CnameBlock: return "cname_block";
    case Action::Dynamic: return "dynamic_rule";
    case Action::Dga: return "dga";
    case Action::Refused: return "refused";
    case Action::RateLimited: return "rate_limited";
    case Action::Rejected: return "rejected";
    case Action::Rebinding: return "rebinding";
    }
    return "answer";
}

std::string address_text(const sockaddr_storage& address) {
    char text[INET6_ADDRSTRLEN] = "?";
    if (address.ss_family == AF_INET) {
        inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in*>(&address)->sin_addr, text, sizeof text);
    } else if (address.ss_family == AF_INET6) {
        inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6*>(&address)->sin6_addr, text, sizeof text);
    }
    return text;
}

std::string json_string(std::string_view text) {
    std::string out = "\"";
    for (const char c : text) {
        const auto byte = static_cast<unsigned char>(c);
        if (c == '"' || c == '\\') {
            out += '\\';
            out += c;
        } else if (byte < 0x20 || byte > 0x7E) {  // names are escaped ASCII already; anything else, safely
            char escaped[8];
            std::snprintf(escaped, sizeof escaped, "\\u%04x", byte);
            out += escaped;
        } else {
            out += c;
        }
    }
    return out + "\"";
}

namespace {

std::string_view transport_name(net::Transport transport) {
    switch (transport) {
    case net::Transport::Udp: return "udp";
    case net::Transport::Tcp: return "tcp";
    case net::Transport::Dot: return "dot";
    case net::Transport::Doh: return "doh";
    }
    return "udp";
}

/// The name as ml/tunnel/pcap.py writes it: Name::to_string without the root's dot.
std::string name_text(const Name& name) {
    std::string text = name.to_string();
    if (text.size() > 1 && text.back() == '.') text.pop_back();
    return text;
}

}  // namespace

std::string to_json(const QueryEvent& event) {
    const auto micros =
        std::chrono::duration_cast<std::chrono::microseconds>(event.time.time_since_epoch()).count();
    char timestamp[32];
    std::snprintf(timestamp, sizeof timestamp, "%lld.%06lld", static_cast<long long>(micros / 1000000),
                  static_cast<long long>(micros % 1000000));
    std::string out = R"({"type":"query","timestamp":)";
    out += timestamp;
    out += R"(,"client":)" + json_string(address_text(event.client));
    out += R"(,"transport":")" + std::string(transport_name(event.transport)) + '"';
    out += R"(,"qname":)" + json_string(name_text(event.question.qname));
    out += R"(,"qtype":")" + type_name(event.question.qtype) + '"';
    out += R"(,"rcode":")" + rcode_name(event.rcode) + '"';
    out += R"(,"answers":)" + std::to_string(event.answers);
    out += R"(,"response_size":)" + std::to_string(event.response_size);
    out += R"(,"latency_us":)" + std::to_string(event.latency_us);
    out += R"(,"action":")" + std::string(action_name(event.action)) + '"';
    if (!event.rule.empty()) out += R"(,"rule":)" + json_string(event.rule);
    if (event.dga) {
        char score[32];
        std::snprintf(score, sizeof score, "%.6f", *event.dga);
        out += R"(,"dga":)";
        out += score;
    }
    return out + "}";
}

}  // namespace dnsentinel::telemetry
