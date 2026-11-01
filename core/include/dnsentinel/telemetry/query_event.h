#pragma once
/// @file telemetry/query_event.h
/// One answered query, as the slow path and the query log see it (README
/// §7.10): who asked what, how it was answered, and which check decided.
///
/// The JSON line is what ml/tunnel trained on: the name in the resolver's
/// text form without the trailing dot, the type and rcode as mnemonics with
/// the same spellings as ml/tunnel/pcap.py, and the response's size in
/// bytes. analyzer/live.py reads it.

#include "dnsentinel/net/query_handler.h"
#include "dnsentinel/types.h"

#include <sys/socket.h>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace dnsentinel::telemetry {

/// Which check decided a query's answer.
enum class Action : uint8_t {
    Answer,       // resolved (from the cache or upstream)
    Block,        // the name is on a block list
    CnameBlock,   // a name in the answer's CNAME chain is
    Dynamic,      // a dynamic rule from the slow path covers it
    Dga,          // the DGA classifier flagged it, in enforce mode
    Refused,      // the client is outside the allowed subnets
    RateLimited,  // the client is over its rate limit
    Rejected,     // a query we don't answer (a zone transfer, a bad class...)
    Rebinding,    // only private addresses were left, so NXDOMAIN
};

struct QueryEvent {
    std::chrono::system_clock::time_point time;  // when the query arrived
    sockaddr_storage                      client{};
    net::Transport                        transport = net::Transport::Udp;
    Question                              question;
    uint8_t                               rcode         = 0;
    uint16_t                              answers       = 0;  // records in the answer section
    size_t                                response_size = 0;  // bytes of the DNS message sent back
    uint32_t                              latency_us    = 0;  // query in to answer out
    Action                                action        = Action::Answer;
    std::string                           rule;  // the rule behind a block, if any
    std::optional<double>                 dga;   // the DGA score, if the classifier scored the name
};

/// The event as one line of JSON, without the newline. `client`, if given,
/// stands in for the address (the query log's anonymised label).
[[nodiscard]] std::string to_json(const QueryEvent& event, std::string_view client = {});

/// "A", "TXT", "TYPE65399": the spellings ml/tunnel/pcap.py uses.
[[nodiscard]] std::string type_name(uint16_t qtype);
/// "NOERROR", "NXDOMAIN", "RCODE9".
[[nodiscard]] std::string rcode_name(uint8_t rcode);
[[nodiscard]] std::string_view action_name(Action action);
/// The client's address as text, without the port.
[[nodiscard]] std::string address_text(const sockaddr_storage& address);
/// `text` as a JSON string literal, quotes included.
[[nodiscard]] std::string json_string(std::string_view text);

}  // namespace dnsentinel::telemetry
