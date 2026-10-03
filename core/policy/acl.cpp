/// @file policy/acl.cpp
/// CIDR parsing and matching.

#include "dnsentinel/policy/acl.h"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <algorithm>
#include <charconv>
#include <cstring>

namespace dnsentinel::policy {

namespace {

size_t address_bytes(sa_family_t family) { return family == AF_INET ? 4 : 16; }

/// Clear every bit past the first `prefix`.
void mask(std::array<uint8_t, 16>& bytes, size_t length, uint8_t prefix) {
    for (size_t i = 0; i < length; ++i) {
        const int keep = std::clamp(static_cast<int>(prefix) - static_cast<int>(i * 8), 0, 8);
        bytes[i] &= static_cast<uint8_t>(0xFF00 >> keep);
    }
}

}  // namespace

std::optional<IpAddress> ip_address(const sockaddr_storage& client) {
    IpAddress ip;
    if (client.ss_family == AF_INET) {
        ip.family = AF_INET;
        std::memcpy(ip.bytes.data(), &reinterpret_cast<const sockaddr_in*>(&client)->sin_addr, 4);
        return ip;
    }
    if (client.ss_family == AF_INET6) {
        const auto& a6 = reinterpret_cast<const sockaddr_in6*>(&client)->sin6_addr;
        if (IN6_IS_ADDR_V4MAPPED(&a6)) {
            ip.family = AF_INET;
            std::memcpy(ip.bytes.data(), a6.s6_addr + 12, 4);
        } else {
            ip.family = AF_INET6;
            std::memcpy(ip.bytes.data(), a6.s6_addr, 16);
        }
        return ip;
    }
    return std::nullopt;  // not an IP client
}

IpAddress IpAddress::network(uint8_t prefix) const {
    IpAddress net = *this;
    mask(net.bytes, address_bytes(family), prefix);
    return net;
}

std::string IpAddress::to_string() const {
    char text[INET6_ADDRSTRLEN] = "?";
    if (family == AF_INET || family == AF_INET6) inet_ntop(family, bytes.data(), text, sizeof text);
    return text;
}

size_t IpAddressHash::operator()(const IpAddress& a) const noexcept {
    uint64_t h = 1469598103934665603ULL ^ a.family;  // FNV-1a
    for (uint8_t b : a.bytes) h = (h ^ b) * 1099511628211ULL;
    return static_cast<size_t>(h);
}

bool Subnet::contains(const sockaddr_storage& client) const {
    auto ip = ip_address(client);
    if (!ip || ip->family != family) return false;  // not an IP client, or the other family
    return ip->network(prefix).bytes == network;
}

std::string Subnet::to_string() const {
    char text[INET6_ADDRSTRLEN] = {};
    inet_ntop(family, network.data(), text, sizeof text);
    return std::string(text) + "/" + std::to_string(prefix);
}

std::expected<Subnet, std::string> parse_subnet(std::string_view text) {
    const std::string quoted = "'" + std::string(text) + "'";
    const size_t      slash  = text.find('/');
    const std::string address(text.substr(0, slash));

    Subnet subnet;
    if (inet_pton(AF_INET, address.c_str(), subnet.network.data()) == 1) {
        subnet.family = AF_INET;
    } else if (inet_pton(AF_INET6, address.c_str(), subnet.network.data()) == 1) {
        subnet.family = AF_INET6;
    } else {
        return std::unexpected(quoted + " is not an IP address or a subnet like 192.168.0.0/16");
    }

    const size_t bits = address_bytes(subnet.family) * 8;
    subnet.prefix     = static_cast<uint8_t>(bits);
    if (slash != std::string_view::npos) {
        const std::string_view digits = text.substr(slash + 1);
        unsigned               prefix = 0;
        auto [end, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), prefix);
        if (digits.empty() || ec != std::errc{} || end != digits.data() + digits.size() || prefix > bits) {
            return std::unexpected(quoted + ": the prefix length must be 0 to " + std::to_string(bits));
        }
        subnet.prefix = static_cast<uint8_t>(prefix);
    }

    Subnet masked = subnet;
    mask(masked.network, address_bytes(subnet.family), subnet.prefix);
    if (masked.network != subnet.network) {
        return std::unexpected(quoted + " has host bits set; did you mean " + masked.to_string() + "?");
    }
    return subnet;
}

std::vector<Subnet> AccessConfig::localhost() {
    return {*parse_subnet("127.0.0.0/8"), *parse_subnet("::1/128")};
}

bool AccessControl::allows(const sockaddr_storage& client) const {
    return std::any_of(config_.allow.begin(), config_.allow.end(),
                       [&](const Subnet& s) { return s.contains(client); });
}

}  // namespace dnsentinel::policy
